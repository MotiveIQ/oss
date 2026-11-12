package s3v1

import (
	"context"
	"io"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

type downloadFixture struct {
	grpc.ClientStream
	messages []*GetObjectResponse
	err      error
}

func (s *downloadFixture) RecvMsg(m any) error {
	if len(s.messages) == 0 {
		return s.err
	}
	proto.Reset(m.(proto.Message))
	proto.Merge(m.(proto.Message), s.messages[0])
	s.messages = s.messages[1:]
	return nil
}
func TestDownloadRequiresFramingLengthAndStatus(t *testing.T) {
	metadata := func(n uint64) *GetObjectResponse {
		return &GetObjectResponse{Frame: &GetObjectResponse_Metadata{Metadata: &ObjectMetadata{ContentLength: n}}}
	}
	data := func(n int) *GetObjectResponse {
		return &GetObjectResponse{Frame: &GetObjectResponse_Data{Data: make([]byte, n)}}
	}
	for _, tc := range []struct {
		name   string
		frames []*GetObjectResponse
		err    error
		want   codes.Code
	}{
		{"valid", []*GetObjectResponse{metadata(4), data(4)}, io.EOF, codes.OK},
		{"empty", []*GetObjectResponse{metadata(0)}, io.EOF, codes.OK},
		{"missing metadata", []*GetObjectResponse{data(4)}, io.EOF, codes.DataLoss},
		{"no messages", nil, io.EOF, codes.DataLoss},
		{"duplicate metadata", []*GetObjectResponse{metadata(0), metadata(0)}, io.EOF, codes.DataLoss},
		{"short", []*GetObjectResponse{metadata(5), data(4)}, io.EOF, codes.DataLoss},
		{"excess", []*GetObjectResponse{metadata(3), data(4)}, io.EOF, codes.DataLoss},
		{"oversize", []*GetObjectResponse{metadata(65537), data(65537)}, io.EOF, codes.DataLoss},
		{"empty frame", []*GetObjectResponse{{}}, io.EOF, codes.DataLoss},
		{"failed status", []*GetObjectResponse{metadata(4), data(4)}, status.Error(codes.Unavailable, "lost"), codes.Unavailable},
		{"cancelled", []*GetObjectResponse{metadata(0)}, status.Error(codes.Canceled, "cancelled"), codes.Canceled},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			stream := &downloadStream{ClientStream: &downloadFixture{messages: tc.frames, err: tc.err}, cancel: cancel}
			var err error
			for err == nil {
				_, err = stream.Recv()
			}
			if tc.want == codes.OK {
				if err != io.EOF {
					t.Fatal(err)
				}
			} else if status.Code(err) != tc.want {
				t.Fatal(err)
			}
			if ctx.Err() == nil {
				t.Fatal("terminal receive did not close stream")
			}
		})
	}
}
