package motiveiq

import (
	"context"
	"net/http"
	"sync"
	"time"

	sdktransport "github.com/MotiveIQ/public/platform/iam/sdk/internal/transport"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"github.com/MotiveIQ/public/platform/iam/internal/proof"
	"github.com/MotiveIQ/public/platform/iam/internal/proofgrpc"
)

// proofStreamInterceptor returns a client stream before it retrieves
// credentials or opens the transport stream. The first SendMsg signs the
// frozen protobuf frame, attaches exclusive authentication metadata,
// opens the stream, and forwards that same frame.
//
// Without explicit signed-upload registration, this profile authenticates only
// the first request frame. Later request
// frames and all response frames have no application proof; their integrity
// depends on the configured transport and its trusted termination points.
// HTTP/2 itself provides no authentication. Bidirectional streams are rejected.
// See platform/iam/STREAM_AUTHENTICATION.md for the registered per-message signed-upload profile.
func (r *clientRuntime) proofStreamInterceptor(serviceKey, origin string, creds *SessionCredentials, options RequestProofOptions) grpc.StreamClientInterceptor {
	return func(ctx context.Context, desc *grpc.StreamDesc, cc *grpc.ClientConn, method string, streamer grpc.Streamer, opts ...grpc.CallOption) (grpc.ClientStream, error) {
		if desc == nil {
			return nil, status.Error(codes.Internal, "motiveiq: streaming RPC has no descriptor")
		}
		if desc.ClientStreams && desc.ServerStreams {
			return nil, status.Errorf(codes.Unimplemented, "motiveiq: proof authentication does not support bidirectional streaming gRPC (%s %s)", serviceKey, method)
		}
		if !desc.ClientStreams && !desc.ServerStreams {
			return nil, status.Errorf(codes.Internal, "motiveiq: invalid non-streaming descriptor for streaming RPC (%s %s)", serviceKey, method)
		}
		if err := sdktransport.EnsureNoOutgoingAuthentication(ctx); err != nil {
			return nil, status.Error(codes.InvalidArgument, err.Error())
		}
		base := &lazyProofClientStream{
			ctx:          ctx,
			desc:         desc,
			cc:           cc,
			method:       method,
			origin:       origin,
			creds:        creds,
			now:          r.cfg.now,
			streamer:     streamer,
			callOptions:  append([]grpc.CallOption(nil), opts...),
			proofOptions: sdktransport.CopyProofOptions(options),
		}
		if registered, ok := ctx.Value(signedUploadMethodKey{}).(string); ok {
			if registered != method || !desc.ClientStreams || desc.ServerStreams {
				return nil, status.Error(codes.InvalidArgument, "invalid signed upload registration")
			}
			return &signedUploadClientStream{lazyProofClientStream: base}, nil
		}
		return base, nil
	}
}

// lazyProofClientStream defers the one operation that gRPC's Streamer would
// normally perform eagerly. SendMsg and CloseSend are not safe concurrently by
// gRPC contract; mu additionally makes a concurrent early RecvMsg wait until
// first-frame initialization finishes.
type lazyProofClientStream struct {
	mu sync.Mutex

	ctx          context.Context
	desc         *grpc.StreamDesc
	cc           *grpc.ClientConn
	method       string
	origin       string
	creds        *SessionCredentials
	now          func() time.Time
	streamer     grpc.Streamer
	callOptions  []grpc.CallOption
	proofOptions RequestProofOptions

	stream      grpc.ClientStream
	terminalErr error
}

func (s *lazyProofClientStream) Header() (metadata.MD, error) {
	stream, err := s.openedStream("read stream headers")
	if err != nil {
		return nil, err
	}
	return stream.Header()
}

func (s *lazyProofClientStream) Trailer() metadata.MD {
	s.mu.Lock()
	stream := s.stream
	s.mu.Unlock()
	if stream == nil {
		return nil
	}
	return stream.Trailer()
}

func (s *lazyProofClientStream) CloseSend() error {
	s.mu.Lock()
	if s.stream != nil {
		stream := s.stream
		s.mu.Unlock()
		return stream.CloseSend()
	}
	if s.terminalErr == nil {
		s.terminalErr = streamFirstMessageRequired("close the send direction")
	}
	err := s.terminalErr
	s.mu.Unlock()
	return err
}

func (s *lazyProofClientStream) Context() context.Context {
	s.mu.Lock()
	stream := s.stream
	ctx := s.ctx
	s.mu.Unlock()
	if stream != nil {
		return stream.Context()
	}
	return ctx
}

func (s *lazyProofClientStream) SendMsg(message any) error {
	s.mu.Lock()
	if s.terminalErr != nil {
		err := s.terminalErr
		s.mu.Unlock()
		return err
	}
	if s.stream != nil {
		stream := s.stream
		s.mu.Unlock()
		return stream.SendMsg(message)
	}

	stream, wireRequest, err := s.openWithFirstMessage(message)
	if err != nil {
		s.terminalErr = err
		s.mu.Unlock()
		return err
	}
	s.stream = stream
	s.mu.Unlock()
	return stream.SendMsg(wireRequest)
}

func (s *lazyProofClientStream) RecvMsg(message any) error {
	stream, err := s.openedStream("receive a response")
	if err != nil {
		return err
	}
	return stream.RecvMsg(message)
}

func (s *lazyProofClientStream) openedStream(operation string) (grpc.ClientStream, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stream != nil {
		return s.stream, nil
	}
	if s.terminalErr != nil {
		return nil, s.terminalErr
	}
	if err := s.ctx.Err(); err != nil {
		return nil, status.FromContextError(err).Err()
	}
	return nil, streamFirstMessageRequired(operation)
}

func streamFirstMessageRequired(operation string) error {
	return status.Errorf(codes.FailedPrecondition, "motiveiq: cannot %s before sending the first authenticated protobuf message", operation)
}

func (s *lazyProofClientStream) openWithFirstMessage(request any) (grpc.ClientStream, any, error) {
	if s.creds == nil {
		return nil, nil, status.Error(codes.Internal, "motiveiq: streaming credentials are not configured")
	}
	if s.streamer == nil {
		return nil, nil, status.Error(codes.Internal, "motiveiq: streaming transport is not configured")
	}
	message, ok := request.(proto.Message)
	if !ok || message == nil || !message.ProtoReflect().IsValid() {
		return nil, nil, status.Error(codes.Internal, "motiveiq: proof signing requires a protobuf request")
	}
	wireRequest, requestDigest, wireOptions, err := proofgrpc.Encode(message, s.proofOptions.VersionNumber())
	if err != nil {
		return nil, nil, status.Errorf(codes.Internal, "motiveiq: request encoding: %v", err)
	}
	generation, err := s.creds.retrieve(s.ctx)
	if err != nil {
		return nil, nil, err
	}
	if generation == nil || generation.signer == nil {
		return nil, nil, status.Error(codes.Unauthenticated, "motiveiq: credentials are not proof-bound")
	}
	targetURI, err := proofTargetURI(s.origin, s.method)
	if err != nil {
		return nil, nil, status.Errorf(codes.Internal, "motiveiq: proof target: %v", err)
	}
	md, _ := metadata.FromOutgoingContext(s.ctx)
	fields, err := sdktransport.SignedGRPCMetadata(md, s.proofOptions.SignedMetadata)
	if err != nil {
		return nil, nil, status.Error(codes.InvalidArgument, err.Error())
	}
	issuedAt := s.now()
	proofExpiresAt := issuedAt.UTC().Truncate(time.Second).Add(proof.MaxLifetime)
	if generation.expiresAt.Before(proofExpiresAt) {
		proofExpiresAt = generation.expiresAt
	}
	compact, err := generation.signer.SignUntil(proof.Binding{
		Version:     s.proofOptions.VersionNumber(),
		Metadata:    fields,
		Transport:   proof.TransportGRPC,
		Operation:   s.method,
		Method:      http.MethodPost,
		TargetURI:   targetURI,
		RequestHash: requestDigest,
		BindToken:   true,
		TokenHash:   proof.Digest([]byte(generation.token)),
	}, issuedAt, proofExpiresAt)
	if err != nil {
		return nil, nil, status.Errorf(codes.Internal, "motiveiq: sign request proof: %v", err)
	}
	ctx, err := withRequestAuthentication(s.ctx, generation.token, compact)
	if err != nil {
		return nil, nil, status.Error(codes.InvalidArgument, err.Error())
	}
	stream, err := s.streamer(ctx, s.desc, s.cc, s.method, append(s.callOptions, wireOptions...)...)
	if err != nil {
		return nil, nil, err
	}
	if stream == nil {
		return nil, nil, status.Errorf(codes.Internal, "motiveiq: streaming transport for %s returned no stream", s.method)
	}
	return stream, wireRequest, nil
}
