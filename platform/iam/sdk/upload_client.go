package motiveiq

import (
	"context"
	"errors"
	"io"
	"sync"
	"time"

	sdktransport "github.com/MotiveIQ/public/platform/iam/sdk/internal/transport"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"github.com/MotiveIQ/public/platform/iam/internal/proof"
	"github.com/MotiveIQ/public/platform/iam/internal/proofstream"
)

type signedUploadMethodKey struct{}

// SignedUploadClientStream is the typed API facade's shared-SDK extension point.
// First SendMsg is an application header; later messages are DATA. CloseSend
// authenticates completion. Credentials and metadata remain fixed for the call.
func (c *Config) SignedUploadClientStream(ctx context.Context, serviceKey, endpoint, origin, override, method string, opts ...grpc.CallOption) (grpc.ClientStream, error) {
	ctx = context.WithValue(ctx, signedUploadMethodKey{}, method)
	return c.GRPCClientConn(serviceKey, endpoint, origin, override).NewStream(ctx, &grpc.StreamDesc{ClientStreams: true}, method, opts...)
}

type signedUploadClientStream struct {
	*lazyProofClientStream
	sendMu  sync.Mutex
	encoder *proofstream.Encoder
	cancel  context.CancelFunc
	closed  bool
}

func (s *signedUploadClientStream) SendMsg(message any) error {
	s.sendMu.Lock()
	defer s.sendMu.Unlock()
	frame, err := s.prepare(message)
	if err != nil {
		return err
	}
	return s.send(frame)
}
func (s *signedUploadClientStream) prepare(message any) (any, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.terminalErr != nil {
		return nil, s.terminalErr
	}
	if s.closed {
		return nil, status.Error(codes.FailedPrecondition, "upload already finished")
	}
	m, ok := message.(proto.Message)
	if !ok || m == nil || !m.ProtoReflect().IsValid() {
		return nil, s.failLocked(status.Error(codes.InvalidArgument, "upload requires a protobuf message"))
	}
	if proto.Size(m) > proofstream.MaxPayload {
		return nil, s.failLocked(status.Error(codes.ResourceExhausted, "upload payload exceeds limit"))
	}
	payload, err := proto.Marshal(m)
	if err != nil {
		return nil, s.failLocked(err)
	}
	first := s.stream == nil
	if first {
		if err = s.open(); err != nil {
			return nil, s.failLocked(err)
		}
	}
	var frame any
	if first {
		frame, err = s.encoder.Open(payload)
	} else {
		frame, err = s.encoder.Data(payload)
	}
	if err != nil {
		return nil, s.failLocked(err)
	}
	return frame, nil
}
func (s *signedUploadClientStream) send(frame any) error {
	// Do not hold the state mutex across flow-controlled I/O: RecvMsg and
	// Context must remain usable concurrently with a blocked SendMsg.
	if err := s.stream.SendMsg(frame); err != nil {
		s.mu.Lock()
		defer s.mu.Unlock()
		return s.failLocked(err)
	}
	return nil
}
func (s *signedUploadClientStream) failLocked(err error) error {
	s.terminalErr = err
	// SendMsg's EOF means the server has a status to read. Preserve that status
	// (e.g. PermissionDenied), rather than replacing it with local cancellation.
	if s.cancel != nil && !errors.Is(err, io.EOF) {
		s.cancel()
	}
	return err
}
func (s *signedUploadClientStream) open() error {
	gen, err := s.creds.retrieve(s.ctx)
	if err != nil {
		return err
	}
	if gen == nil || gen.signer == nil {
		return status.Error(codes.Unauthenticated, "upload requires proof-bound credentials")
	}
	target, err := proofTargetURI(s.origin, s.method)
	if err != nil {
		return err
	}
	md, _ := metadata.FromOutgoingContext(s.ctx)
	fields, err := sdktransport.SignedGRPCMetadata(md, s.proofOptions.SignedMetadata)
	if err != nil {
		return err
	}
	deadline := s.now().Add(time.Hour)
	if gen.expiresAt.Before(deadline) {
		deadline = gen.expiresAt
	}
	if d, ok := s.ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	deadline = deadline.Truncate(time.Second)
	s.encoder, err = proofstream.NewEncoder(gen.signer, gen.token, proof.Binding{Operation: s.method, TargetURI: target, Metadata: fields}, deadline, s.now)
	if err != nil {
		return err
	}
	s.ctx, s.cancel = context.WithDeadline(s.ctx, deadline)
	// A zero retry buffer commits the stream as soon as OPEN is sent. Config also
	// disables service-config retry/hedging; a failed upload is never replayed.
	opts := append(append([]grpc.CallOption(nil), s.callOptions...), grpc.MaxRetryRPCBufferSize(0), grpc.MaxCallSendMsgSize(proofstream.MaxEnvelope))
	s.stream, err = s.streamer(s.ctx, s.desc, s.cc, s.method, opts...)
	return err
}
func (s *signedUploadClientStream) CloseSend() error {
	s.sendMu.Lock()
	defer s.sendMu.Unlock()
	frame, err := s.prepareFinish()
	if err != nil {
		return err
	}
	if frame == nil {
		return nil
	}
	if err = s.send(frame); err != nil {
		return err
	}
	if err = s.stream.CloseSend(); err != nil {
		s.mu.Lock()
		defer s.mu.Unlock()
		return s.failLocked(err)
	}
	return nil
}
func (s *signedUploadClientStream) prepareFinish() (any, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.terminalErr != nil {
		return nil, s.terminalErr
	}
	if s.closed {
		return nil, nil
	}
	if s.stream == nil {
		return nil, s.failLocked(streamFirstMessageRequired("finish upload"))
	}
	if err := s.ctx.Err(); err != nil {
		return nil, s.failLocked(status.FromContextError(err).Err())
	}
	frame, err := s.encoder.Finish()
	if err != nil {
		return nil, s.failLocked(err)
	}
	s.closed = true
	return frame, nil
}
func (s *signedUploadClientStream) RecvMsg(message any) error {
	stream, err := s.openedStream("receive upload result")
	if err != nil {
		return err
	}
	// Client-streaming gRPC receives exactly one response and validates final
	// status in RecvMsg; the signed deadline covers a lost/blocked response too.
	err = stream.RecvMsg(message)
	s.mu.Lock()
	if s.cancel != nil {
		s.cancel()
	}
	s.mu.Unlock()
	return err
}
