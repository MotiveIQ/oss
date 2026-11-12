package proofgrpc

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/encoding/gzip"
	"google.golang.org/grpc/mem"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/MotiveIQ/public/platform/iam/internal/proof"
)

const echoMethod = "/test.Echo/Call"

func echoBinding(version int, payload []byte) proof.Binding {
	return proof.Binding{Version: version, Transport: proof.TransportGRPC, Operation: echoMethod,
		Method: "POST", TargetURI: "https://echo.test" + echoMethod, RequestHash: proof.Digest(payload)}
}

func TestWireProofProfiles(t *testing.T) {
	for _, captured := range []bool{false, true} {
		t.Run(fmt.Sprintf("capture=%t", captured), func(t *testing.T) {
			now := time.Now().UTC().Truncate(time.Second)
			signer, err := proof.GenerateSigner(nil)
			if err != nil {
				t.Fatal(err)
			}
			var calls atomic.Int64
			var opts []grpc.ServerOption
			if captured {
				opts = append(opts, ServerOption())
			}
			server := grpc.NewServer(opts...)
			desc := &grpc.ServiceDesc{ServiceName: "test.Echo", HandlerType: (*interface{})(nil), Methods: []grpc.MethodDesc{{
				MethodName: "Call", Handler: func(_ any, ctx context.Context, decode func(any) error, _ grpc.UnaryServerInterceptor) (any, error) {
					request := new(wrapperspb.StringValue)
					if err := decode(request); err != nil {
						return nil, err
					}
					md, _ := metadata.FromIncomingContext(ctx)
					values := md.Get("dpop")
					if len(values) != 1 {
						return nil, status.Error(codes.Unauthenticated, "proof")
					}
					version, digest, err := RequestDigest(ctx, request, values[0])
					if err != nil {
						return nil, status.Error(codes.Unauthenticated, "digest")
					}
					binding := echoBinding(version, nil)
					binding.RequestHash = digest
					if _, err := proof.NewVerifier(func() time.Time { return now }).Verify(values[0], binding); err != nil {
						return nil, status.Error(codes.Unauthenticated, "proof")
					}
					calls.Add(1)
					return request, nil
				},
			}}}
			var registrar grpc.ServiceRegistrar = server
			if captured {
				registrar = Registrar(server)
			}
			registrar.RegisterService(desc, struct{}{})
			listener := bufconn.Listen(1 << 20)
			go func() { _ = server.Serve(listener) }()
			t.Cleanup(server.Stop)
			conn, err := grpc.NewClient("passthrough:///echo", grpc.WithTransportCredentials(insecure.NewCredentials()),
				grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return listener.Dial() }), grpc.WithDisableRetry())
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = conn.Close() })
			// Same logical string in three wire encodings: duplicate scalar values,
			// an unknown field, and the ordinary generated encoding.
			canonical := []byte{0x0a, 1, 'a'}
			duplicate := append(append([]byte(nil), canonical...), canonical...)
			unknown := append(append([]byte(nil), canonical...), 0x10, 1)
			for _, compression := range []string{"", gzip.Name} {
				for _, tc := range []struct {
					name         string
					version      int
					signed, sent []byte
					allowed      bool
				}{
					{"v3 canonical", 3, canonical, canonical, captured},
					{"v3 duplicate scalar", 3, duplicate, duplicate, captured},
					{"v3 unknown", 3, unknown, unknown, captured},
					{"v3 changed encoding", 3, canonical, duplicate, false},
					{"v3 stripped unknown", 3, unknown, canonical, false},
					{"v3 empty", 3, nil, nil, captured},
				} {
					t.Run(compression+"/"+tc.name, func(t *testing.T) {
						compact, err := signer.Sign(echoBinding(tc.version, tc.signed), now)
						if err != nil {
							t.Fatal(err)
						}
						ctx := metadata.NewOutgoingContext(context.Background(), metadata.Pairs("dpop", compact))
						ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
						defer cancel()
						options := []grpc.CallOption{grpc.ForceCodecV2(codec{})}
						if compression != "" {
							options = append(options, grpc.UseCompressor(compression))
						}
						before := calls.Load()
						err = conn.Invoke(ctx, echoMethod, &encodedRequest{tc.sent}, new(wrapperspb.StringValue), options...)
						if tc.allowed {
							if err != nil || calls.Load() != before+1 {
								t.Fatalf("call = %v, handler count %d", err, calls.Load())
							}
						} else if status.Code(err) != codes.Unauthenticated || calls.Load() != before {
							t.Fatalf("unauthenticated call = %v, handler count %d", err, calls.Load())
						}
					})
				}
			}
			if captured {
				var wg sync.WaitGroup
				for i := 0; i < 32; i++ {
					wg.Add(1)
					go func() {
						defer wg.Done()
						message := wrapperspb.String(fmt.Sprintf("request-%d", i))
						wire, digest, options, err := Encode(message, proof.Version3)
						if err != nil {
							t.Error(err)
							return
						}
						binding := echoBinding(3, nil)
						binding.RequestHash = digest
						compact, err := signer.Sign(binding, now)
						if err != nil {
							t.Error(err)
							return
						}
						ctx, cancel := context.WithTimeout(metadata.NewOutgoingContext(context.Background(), metadata.Pairs("dpop", compact)), 5*time.Second)
						defer cancel()
						reply := new(wrapperspb.StringValue)
						if err := conn.Invoke(ctx, echoMethod, wire, reply, options...); err != nil || reply.Value != message.Value {
							t.Errorf("concurrent call: %v, %q", err, reply.Value)
						}
					}()
				}
				wg.Wait()
			}
		})
	}
}

func TestEncodeFreezesMapPayload(t *testing.T) {
	message, err := structpb.NewStruct(map[string]any{"a": "one", "b": "two"})
	if err != nil {
		t.Fatal(err)
	}
	wire, digest, _, err := Encode(message, proof.Version3)
	if err != nil {
		t.Fatal(err)
	}
	frozen := append([]byte(nil), wire.(*encodedRequest).payload...)
	message.Fields["a"] = structpb.NewStringValue("changed after signing")
	data, err := (codec{}).Marshal(wire)
	if err != nil {
		t.Fatal(err)
	}
	defer data.Free()
	if !bytes.Equal(data.Materialize(), frozen) || proof.Digest(data.Materialize()) != digest {
		t.Fatal("signed payload changed")
	}
	decoded := new(structpb.Struct)
	if err := proto.Unmarshal(data.Materialize(), decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Fields["a"].GetStringValue() != "one" {
		t.Fatal("codec reserialized mutable request")
	}
}

func TestReceivePreservesFirstFrameEvidence(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	signer, err := proof.GenerateSigner(nil)
	if err != nil {
		t.Fatal(err)
	}
	// Duplicate scalar fields and an unknown field survive the wire digest even
	// though decoding and reserialization collapse the duplicated scalar.
	wire := []byte{0x0a, 1, 'a', 0x0a, 1, 'b', 0x10, 1}
	message := new(wrapperspb.StringValue)
	ctx, err := Receive(context.Background(), message, func(destination any) error {
		data := mem.BufferSlice{mem.SliceBuffer(wire)}
		defer data.Free()
		return (codec{}).Unmarshal(data, destination)
	})
	if err != nil || message.Value != "b" {
		t.Fatalf("receive: %v, %v", message, err)
	}
	compact, err := signer.Sign(echoBinding(proof.Version3, wire), now)
	if err != nil {
		t.Fatal(err)
	}
	version, digest, err := RequestDigest(ctx, message, compact)
	if err != nil || version != proof.Version3 || digest != proof.Digest(wire) {
		t.Fatalf("first-frame evidence: %d %x %v", version, digest, err)
	}
	normalized, err := proto.Marshal(message)
	if err != nil || digest == proof.Digest(normalized) {
		t.Fatalf("test requires a different reserialized digest: %x, %v", normalized, err)
	}
	if _, _, err := RequestDigest(ctx, proto.Clone(message), compact); err == nil {
		t.Fatal("evidence reused for a different message")
	}
	if _, err := Receive(context.Background(), message, func(any) error { return nil }); err == nil {
		t.Fatal("receive accepted missing codec evidence")
	}
}
