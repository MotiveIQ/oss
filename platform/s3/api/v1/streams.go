package s3v1

import (
	"context"
	"errors"
	"io"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// SignedUploadConfig is implemented by the IAM SDK. A facade cannot silently
// fall back to the legacy first-frame-only proof profile.
type SignedUploadConfig interface {
	SignedUploadClientStream(context.Context, string, string, string, string, string, ...grpc.CallOption) (grpc.ClientStream, error)
}

func (c *Client) PutObject(ctx context.Context, opts ...grpc.CallOption) (grpc.ClientStreamingClient[PutObjectRequest, PutObjectResponse], error) {
	stream, err := c.cfg.SignedUploadClientStream(ctx, ServiceKey, defaultEndpoint, ServiceOrigin, c.endpoint, DataPlane_PutObject_FullMethodName, opts...)
	if err != nil {
		return nil, err
	}
	return &uploadStream{ClientStream: stream}, nil
}

type uploadStream struct {
	grpc.ClientStream
	opened bool
}

func (s *uploadStream) Send(m *PutObjectRequest) error { return s.SendMsg(m) }
func (s *uploadStream) SendMsg(message any) error {
	m, ok := message.(*PutObjectRequest)
	if !ok || m == nil {
		return status.Error(codes.InvalidArgument, "PutObject requires a request")
	}
	if !s.opened {
		h, ok := m.Frame.(*PutObjectRequest_Header)
		if !ok || h.Header == nil {
			return status.Error(codes.InvalidArgument, "PutObject starts with a header")
		}
		if err := s.ClientStream.SendMsg(h.Header); err != nil {
			return err
		}
		s.opened = true
		return nil
	}
	d, ok := m.Frame.(*PutObjectRequest_Data)
	if !ok {
		return status.Error(codes.InvalidArgument, "PutObject header may appear only once")
	}
	if len(d.Data) > 64*1024 {
		return status.Error(codes.ResourceExhausted, "object chunk exceeds 64 KiB")
	}
	return s.ClientStream.SendMsg(m)
}
func (s *uploadStream) CloseAndRecv() (*PutObjectResponse, error) {
	if err := s.CloseSend(); err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	response := new(PutObjectResponse)
	if err := s.RecvMsg(response); err != nil {
		return nil, err
	}
	return response, nil
}

func (c *Client) GetObject(ctx context.Context, request *GetObjectRequest, opts ...grpc.CallOption) (grpc.ServerStreamingClient[GetObjectResponse], error) {
	ctx, cancel := context.WithCancel(ctx)
	stream, err := c.DataPlaneClient.GetObject(ctx, request, append(opts, grpc.MaxCallRecvMsgSize(96*1024))...)
	if err != nil {
		cancel()
		return nil, err
	}
	return &downloadStream{ClientStream: stream, cancel: cancel}, nil
}

type downloadStream struct {
	grpc.ClientStream
	cancel       context.CancelFunc
	metadataSeen bool
	remaining    uint64
	terminal     error
}

func (s *downloadStream) Recv() (*GetObjectResponse, error) {
	m := new(GetObjectResponse)
	if err := s.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}
func (s *downloadStream) RecvMsg(message any) error {
	if s.terminal != nil {
		return s.terminal
	}
	m, ok := message.(*GetObjectResponse)
	if !ok {
		return status.Error(codes.Internal, "invalid download destination")
	}
	err := s.ClientStream.RecvMsg(m)
	if errors.Is(err, io.EOF) && (!s.metadataSeen || s.remaining != 0) {
		err = status.Error(codes.DataLoss, "incomplete object download")
	}
	if err == nil {
		switch f := m.Frame.(type) {
		case *GetObjectResponse_Metadata:
			if s.metadataSeen || f.Metadata == nil {
				err = status.Error(codes.DataLoss, "unexpected object metadata")
			} else {
				s.metadataSeen = true
				s.remaining = f.Metadata.ContentLength
			}
		case *GetObjectResponse_Data:
			if !s.metadataSeen || len(f.Data) > 64*1024 || uint64(len(f.Data)) > s.remaining {
				err = status.Error(codes.DataLoss, "invalid object data frame")
			} else {
				s.remaining -= uint64(len(f.Data))
			}
		default:
			err = status.Error(codes.DataLoss, "missing object frame")
		}
	}
	if err != nil {
		s.terminal = err
		s.cancel()
	}
	return err
}
