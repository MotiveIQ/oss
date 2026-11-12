package motiveiq

import (
	"context"
	"io"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/encoding"
	"google.golang.org/grpc/interop/grpc_testing"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"github.com/MotiveIQ/public/platform/iam/internal/proof"
	"github.com/MotiveIQ/public/platform/iam/internal/proofgrpc"
)

const proofTestOrigin = "https://deploy.platform.motiveiq.net"

func TestProofStreamClientIsLazyAndBindsFirstFrame(t *testing.T) {
	for _, tc := range []struct {
		name   string
		desc   *grpc.StreamDesc
		method string
		first  proto.Message
		second proto.Message
	}{
		{
			name:   "ServerStreaming",
			desc:   &grpc_testing.TestService_ServiceDesc.Streams[0],
			method: grpc_testing.TestService_StreamingOutputCall_FullMethodName,
			first: &grpc_testing.StreamingOutputCallRequest{
				Payload: &grpc_testing.Payload{Body: []byte("bound-server-stream-request")},
			},
		},
		{
			name:   "ClientStreaming",
			desc:   &grpc_testing.TestService_ServiceDesc.Streams[1],
			method: grpc_testing.TestService_StreamingInputCall_FullMethodName,
			first: &grpc_testing.StreamingInputCallRequest{
				Payload: &grpc_testing.Payload{Body: []byte("bound-first-frame")},
			},
			second: &grpc_testing.StreamingInputCallRequest{
				Payload: &grpc_testing.Payload{Body: []byte("transport-bound-second-frame")},
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			clock := newFakeClock()
			sts, addr := startFakeSTS(t, clock.Now, 15*time.Minute)
			sts.returnProofTokens()
			cfg := newCredentialsConfig(t, clock, addr, writeTokenFile(t, "web-token-1"))
			creds := mustCredentials(t, cfg)

			transport := &recordingProofClientStream{ctx: context.Background(), recvErr: io.EOF, prototype: tc.first}
			streamerCalls := 0
			var outgoing metadata.MD
			stream, err := cfg.clientRuntime.proofStreamInterceptor("test-service", proofTestOrigin, creds, RequestProofOptions{})(
				context.Background(), tc.desc, nil, tc.method,
				func(ctx context.Context, _ *grpc.StreamDesc, _ *grpc.ClientConn, _ string, _ ...grpc.CallOption) (grpc.ClientStream, error) {
					streamerCalls++
					outgoing, _ = metadata.FromOutgoingContext(ctx)
					transport.ctx = ctx
					return transport, nil
				},
			)
			if err != nil {
				t.Fatalf("construct stream: %v", err)
			}
			if calls, _, _, _ := sts.snapshot(); calls != 0 || streamerCalls != 0 {
				t.Fatalf("before first SendMsg: STS calls = %d, streamer calls = %d; want lazy", calls, streamerCalls)
			}
			if err := stream.RecvMsg(&grpc_testing.StreamingInputCallResponse{}); status.Code(err) != codes.FailedPrecondition {
				t.Fatalf("RecvMsg before SendMsg = %v, want FailedPrecondition", err)
			}
			if _, err := stream.Header(); status.Code(err) != codes.FailedPrecondition {
				t.Fatalf("Header before SendMsg = %v, want FailedPrecondition", err)
			}
			if calls, _, _, _ := sts.snapshot(); calls != 0 || streamerCalls != 0 {
				t.Fatalf("early receive opened stream: STS calls = %d, streamer calls = %d", calls, streamerCalls)
			}

			if err := stream.SendMsg(tc.first); err != nil {
				t.Fatalf("first SendMsg: %v", err)
			}
			if calls, _, _, _ := sts.snapshot(); calls != 1 || streamerCalls != 1 {
				t.Fatalf("after first SendMsg: STS calls = %d, streamer calls = %d; want 1, 1", calls, streamerCalls)
			}
			if len(transport.sent) != 1 || !proto.Equal(transport.sent[0], tc.first) {
				t.Fatalf("transport first frame = %v, want %v", transport.sent, tc.first)
			}
			authorizations, proofs := outgoing.Get("authorization"), outgoing.Get("dpop")
			if len(authorizations) != 1 || authorizations[0] != "DPoP session-token-1" || len(proofs) != 1 {
				t.Fatalf("authentication metadata = authorization %v, dpop values %d", authorizations, len(proofs))
			}
			wire, marshalErr := proto.MarshalOptions{Deterministic: true}.Marshal(tc.first)
			if marshalErr != nil {
				t.Fatalf("marshal first frame: %v", marshalErr)
			}
			if _, verifyErr := proof.NewVerifier(clock.Now).Verify(proofs[0], proof.Binding{
				Transport:   proof.TransportGRPC,
				Operation:   tc.method,
				Method:      "POST",
				TargetURI:   proofTestOrigin + tc.method,
				RequestHash: proof.Digest(wire),
				BindToken:   true,
				TokenHash:   proof.Digest([]byte("session-token-1")),
			}); verifyErr != nil {
				t.Fatalf("verify first-frame proof: %v", verifyErr)
			}

			if tc.second != nil {
				if err := stream.SendMsg(tc.second); err != nil {
					t.Fatalf("second SendMsg: %v", err)
				}
				if len(transport.sent) != 2 || !proto.Equal(transport.sent[1], tc.second) {
					t.Fatalf("transport second frame = %v, want %v", transport.sent, tc.second)
				}
				if calls, _, _, _ := sts.snapshot(); calls != 1 || streamerCalls != 1 {
					t.Fatalf("second frame reinitialized stream: STS calls = %d, streamer calls = %d", calls, streamerCalls)
				}
			}
			if err := stream.CloseSend(); err != nil || transport.closeCalls != 1 {
				t.Fatalf("CloseSend = %v, transport calls = %d", err, transport.closeCalls)
			}
			if err := stream.RecvMsg(&grpc_testing.StreamingInputCallResponse{}); err != io.EOF {
				t.Fatalf("RecvMsg after SendMsg = %v, want EOF from transport", err)
			}
		})
	}
}

func TestProofStreamClientRejectsZeroFrameBidiAndConflictingMetadata(t *testing.T) {
	clock := newFakeClock()
	sts, addr := startFakeSTS(t, clock.Now, 15*time.Minute)
	sts.returnProofTokens()
	cfg := newCredentialsConfig(t, clock, addr, writeTokenFile(t, "web-token-1"))
	creds := mustCredentials(t, cfg)
	streamerCalls := 0
	streamer := func(context.Context, *grpc.StreamDesc, *grpc.ClientConn, string, ...grpc.CallOption) (grpc.ClientStream, error) {
		streamerCalls++
		return &recordingProofClientStream{ctx: context.Background()}, nil
	}

	stream, err := cfg.clientRuntime.proofStreamInterceptor("test-service", proofTestOrigin, creds, RequestProofOptions{})(
		context.Background(), &grpc_testing.TestService_ServiceDesc.Streams[1], nil,
		grpc_testing.TestService_StreamingInputCall_FullMethodName, streamer,
	)
	if err != nil {
		t.Fatalf("construct client stream: %v", err)
	}
	if err := stream.CloseSend(); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("zero-frame CloseSend = %v, want FailedPrecondition", err)
	}
	if err := stream.SendMsg(&grpc_testing.StreamingInputCallRequest{}); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("SendMsg after zero-frame CloseSend = %v, want terminal FailedPrecondition", err)
	}
	if err := stream.RecvMsg(&grpc_testing.StreamingInputCallResponse{}); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("RecvMsg after zero-frame CloseSend = %v, want terminal FailedPrecondition", err)
	}

	if bidi, bidiErr := cfg.clientRuntime.proofStreamInterceptor("test-service", proofTestOrigin, creds, RequestProofOptions{})(
		context.Background(), &grpc_testing.TestService_ServiceDesc.Streams[2], nil,
		grpc_testing.TestService_FullDuplexCall_FullMethodName, streamer,
	); status.Code(bidiErr) != codes.Unimplemented || bidi != nil {
		t.Fatalf("bidi stream = (%v, %v), want nil, Unimplemented", bidi, bidiErr)
	}

	conflicting := metadata.NewOutgoingContext(context.Background(), metadata.Pairs("dpop", "application-proof"))
	if got, conflictErr := cfg.clientRuntime.proofStreamInterceptor("test-service", proofTestOrigin, creds, RequestProofOptions{})(
		conflicting, &grpc_testing.TestService_ServiceDesc.Streams[0], nil,
		grpc_testing.TestService_StreamingOutputCall_FullMethodName, streamer,
	); status.Code(conflictErr) != codes.InvalidArgument || got != nil {
		t.Fatalf("conflicting metadata stream = (%v, %v), want nil, InvalidArgument", got, conflictErr)
	}
	if calls, _, _, _ := sts.snapshot(); calls != 0 || streamerCalls != 0 {
		t.Fatalf("rejected streams performed I/O: STS calls = %d, streamer calls = %d", calls, streamerCalls)
	}
}

type recordingProofClientStream struct {
	ctx        context.Context
	sent       []proto.Message
	prototype  proto.Message
	recvErr    error
	closeCalls int
}

func (s *recordingProofClientStream) Header() (metadata.MD, error) {
	return metadata.Pairs("x-test-header", "present"), nil
}

func (s *recordingProofClientStream) Trailer() metadata.MD {
	return metadata.Pairs("x-test-trailer", "present")
}

func (s *recordingProofClientStream) CloseSend() error {
	s.closeCalls++
	return nil
}

func (s *recordingProofClientStream) Context() context.Context {
	return s.ctx
}

func (s *recordingProofClientStream) SendMsg(message any) error {
	data, err := streamTestCodec().Marshal(message)
	if err != nil {
		return err
	}
	defer data.Free()
	decoded := proto.Clone(s.prototype)
	if err := proto.Unmarshal(data.Materialize(), decoded); err != nil {
		return err
	}
	s.sent = append(s.sent, decoded)
	return nil
}

func (s *recordingProofClientStream) RecvMsg(any) error {
	return s.recvErr
}

// Exercise the same codec used by both sides of the real proof transport.
func streamTestCodec() encoding.CodecV2 {
	_, _, options, err := proofgrpc.Encode(&grpc_testing.StreamingInputCallRequest{}, proof.Version3)
	if err != nil {
		panic(err)
	}
	return options[0].(grpc.ForceCodecV2CallOption).CodecV2
}
