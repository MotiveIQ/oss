// Package prooftest supplies wire-level fixtures for authentication tests.
// Its Bazel target is test-only: retired proofs cannot be minted by runtime code.
package prooftest

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net"
	"strings"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/MotiveIQ/public/platform/iam/internal/proof"
	"github.com/MotiveIQ/public/platform/iam/internal/proofgrpc"
)

// Signer can re-sign a v3 fixture as a valid historical v2 proof, so rejection
// tests distinguish retired-profile rejection from an invalid signature.
type Signer struct {
	*proof.Signer
	key ed25519.PrivateKey
}

func NewSigner(t testing.TB) *Signer {
	t.Helper()
	_, key, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := proof.NewSigner(key, nil)
	if err != nil {
		t.Fatal(err)
	}
	return &Signer{Signer: signer, key: key}
}

func (s *Signer) V2(t testing.TB, compact string) string {
	t.Helper()
	parts := strings.Split(compact, ".")
	if len(parts) != 3 {
		t.Fatal("invalid test proof")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatal(err)
	}
	claims["mqi_v"] = 2
	delete(claims, "mqi_metadata")
	payload, err = json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	input := parts[0] + "." + base64.RawURLEncoding.EncodeToString(payload)
	return input + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(s.key, []byte(input)))
}

// CallOption makes manually signed fixture messages use exactly the bytes the
// fixture hashed, including protobuf maps. Production callers use Encode to
// freeze their payload instead; receivers always verify captured wire bytes.
func CallOption() grpc.CallOption { return grpc.ForceCodec(fixtureCodec{}) }

type fixtureCodec struct{}

func (fixtureCodec) Name() string { return "proto" }
func (fixtureCodec) Marshal(v any) ([]byte, error) {
	return proto.MarshalOptions{Deterministic: true}.Marshal(v.(proto.Message))
}
func (fixtureCodec) Unmarshal(b []byte, v any) error { return proto.Unmarshal(b, v.(proto.Message)) }

// Invoke runs an interceptor and handler behind the real proof codec/registrar.
// Unit tests therefore receive the same private byte-capture context as a live
// RPC, without introducing a production API that could forge transport evidence.
func Invoke(ctx context.Context, request any, method string, interceptor grpc.UnaryServerInterceptor, handler grpc.UnaryHandler) (any, error) {
	if interceptor == nil {
		interceptor = func(ctx context.Context, req any, _ *grpc.UnaryServerInfo, next grpc.UnaryHandler) (any, error) {
			return next(ctx, req)
		}
	}
	message, ok := request.(proto.Message)
	if !ok || message == nil {
		return interceptor(ctx, request, &grpc.UnaryServerInfo{FullMethod: method}, handler)
	}
	service, name, _ := strings.Cut(strings.TrimPrefix(method, "/"), "/")
	var response any
	server := grpc.NewServer(proofgrpc.ServerOption())
	proofgrpc.Registrar(server).RegisterService(&grpc.ServiceDesc{
		ServiceName: service, HandlerType: (*interface{})(nil),
		Methods: []grpc.MethodDesc{{MethodName: name, Handler: func(_ any, incoming context.Context, decode func(any) error, _ grpc.UnaryServerInterceptor) (any, error) {
			decoded := message.ProtoReflect().New().Interface()
			if err := decode(decoded); err != nil {
				return nil, err
			}
			var err error
			response, err = interceptor(incoming, decoded, &grpc.UnaryServerInfo{FullMethod: method}, handler)
			return &emptypb.Empty{}, err
		}}},
	}, struct{}{})
	listener := bufconn.Listen(1 << 20)
	go func() { _ = server.Serve(listener) }()
	defer server.Stop()
	defer listener.Close()
	conn, err := grpc.NewClient("passthrough:///fixture", grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return listener.DialContext(ctx) }), grpc.WithDisableRetry())
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	md, _ := metadata.FromIncomingContext(ctx)
	err = conn.Invoke(metadata.NewOutgoingContext(ctx, md), method, request, &emptypb.Empty{}, CallOption())
	return response, err
}
