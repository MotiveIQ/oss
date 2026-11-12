// Package proofgrpc provides the byte-preserving gRPC transport for proof v3.
// The wire payload remains ordinary protobuf; only its digest semantics change.
package proofgrpc

import (
	"context"
	"crypto/sha256"
	"fmt"

	"google.golang.org/grpc"
	"google.golang.org/grpc/encoding"
	_ "google.golang.org/grpc/encoding/proto" // register the standard protobuf codec
	"google.golang.org/grpc/mem"
	"google.golang.org/protobuf/proto"

	"github.com/MotiveIQ/public/platform/iam/internal/proof"
)

type encodedRequest struct{ payload []byte }
type decodingRequest struct {
	message any
	digest  [sha256.Size]byte
	ready   bool
	capture bool
	payload []byte
}
type evidenceKey struct{}

// codec delegates ordinary messages (including responses and health RPCs) to
// grpc-go. Per-call state is carried explicitly in private request wrappers,
// never in a global map or a shared codec field.
type codec struct{}

func (codec) Name() string { return "proto" }

func (codec) Marshal(message any) (mem.BufferSlice, error) {
	if request, ok := message.(*encodedRequest); ok {
		return mem.BufferSlice{mem.SliceBuffer(request.payload)}, nil
	}
	return encoding.GetCodecV2("proto").Marshal(message)
}

func (codec) Unmarshal(data mem.BufferSlice, message any) error {
	if request, ok := message.(*decodingRequest); ok {
		hash := sha256.New()
		for _, buffer := range data {
			_, _ = hash.Write(buffer.ReadOnlyData())
		}
		copy(request.digest[:], hash.Sum(nil))
		if err := encoding.GetCodecV2("proto").Unmarshal(data, request.message); err != nil {
			return err
		}
		if request.capture {
			request.payload = data.Materialize()
		}
		request.ready = true
		return nil
	}
	return encoding.GetCodecV2("proto").Unmarshal(data, message)
}

// Encode freezes the payload before signing. The returned v3 call options must
// be appended after application options so another codec cannot replace it.
func Encode(message proto.Message, version int) (any, [sha256.Size]byte, []grpc.CallOption, error) {
	if !proof.SupportedVersion(version) {
		return nil, [sha256.Size]byte{}, nil, fmt.Errorf("unsupported proof version %d", version)
	}
	bytes, err := proto.Marshal(message)
	if err != nil {
		return nil, [sha256.Size]byte{}, nil, err
	}
	digest := proof.Digest(bytes)

	return &encodedRequest{payload: bytes}, digest, []grpc.CallOption{
		grpc.ForceCodecV2(codec{}), grpc.CallContentSubtype("proto"),
	}, nil
}

// ServerOption must be used together with Registrar. It is scoped to this
// server and never replaces the process-wide registered protobuf codec.
func ServerOption() grpc.ServerOption { return grpc.ForceServerCodecV2(codec{}) }

// Receive captures the exact payload of one stream frame before protobuf
// decoding. The returned context binds its digest to this message, just like
// Registrar does for unary RPCs. The server must install ServerOption.
func Receive(ctx context.Context, message proto.Message, recv func(any) error) (context.Context, error) {
	evidence := &decodingRequest{message: message}
	if err := recv(evidence); err != nil {
		return nil, err
	}
	if !evidence.ready {
		return nil, fmt.Errorf("stream frame requires the proof gRPC transport")
	}
	return context.WithValue(ctx, evidenceKey{}, evidence), nil
}

type registrar struct {
	grpc.ServiceRegistrar
	capture bool
}

// Registrar wraps unary decode functions so their transport digest is available
// in the RPC context. Generated RegisterFooServer functions accept this wrapper;
// generated messages, method names, responses, and service implementations stay
// unchanged. Streaming authentication remains the server's responsibility.
func Registrar(server grpc.ServiceRegistrar) grpc.ServiceRegistrar {
	return registrar{ServiceRegistrar: server}
}

func (r registrar) RegisterService(desc *grpc.ServiceDesc, implementation any) {
	copyDesc := *desc
	copyDesc.Methods = append([]grpc.MethodDesc(nil), desc.Methods...)
	for i := range copyDesc.Methods {
		original := copyDesc.Methods[i].Handler
		copyDesc.Methods[i].Handler = func(srv any, ctx context.Context, decode func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
			evidence := &decodingRequest{capture: r.capture}
			defer func() { clear(evidence.payload) }()
			ctx = context.WithValue(ctx, evidenceKey{}, evidence)
			return original(srv, ctx, func(message any) error {
				evidence.message = message
				return decode(evidence)
			}, interceptor)
		}
	}
	r.ServiceRegistrar.RegisterService(&copyDesc, implementation)
}

// RequestDigest selects exactly one profile; a missing v3 transport digest is
// an error, never an invitation to reserialize or fall back to v2.
func RequestDigest(ctx context.Context, message proto.Message, compact string) (int, [sha256.Size]byte, error) {
	version, err := proof.UnverifiedVersion(compact)
	if err != nil {
		return 0, [sha256.Size]byte{}, err
	}

	evidence, ok := ctx.Value(evidenceKey{}).(*decodingRequest)
	if !ok || !evidence.ready || evidence.message != message {
		return 0, [sha256.Size]byte{}, fmt.Errorf("v3 requires the proof gRPC transport")
	}
	return version, evidence.digest, nil
}

// SourceRegistrar retains exact unary request bytes for an internal delegation
// exchange, then clears that owned buffer when the handler returns. Opt in only
// on services that need source evidence; ordinary services retain only a digest.
func SourceRegistrar(server grpc.ServiceRegistrar) grpc.ServiceRegistrar {
	return registrar{ServiceRegistrar: server, capture: true}
}
func SourcePayload(ctx context.Context) ([]byte, bool) {
	e, ok := ctx.Value(evidenceKey{}).(*decodingRequest)
	if !ok || !e.ready || !e.capture {
		return nil, false
	}
	return e.payload, true
}

// EncodePayload freezes already encoded bytes without reserializing maps.
func EncodePayload(payload []byte) (any, [sha256.Size]byte, []grpc.CallOption) {
	return &encodedRequest{payload: payload}, proof.Digest(payload), []grpc.CallOption{grpc.ForceCodecV2(codec{}), grpc.CallContentSubtype("proto")}
}
