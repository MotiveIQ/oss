package s3v1

import (
	"context"
	"errors"
	"fmt"
	"io"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Upload stores body with the header's metadata and conditions. ContentLength
// must be present, including for empty objects, and match the entire body.
// Upload handles bounded chunks and signed stream completion. It cancels the
// stream without committing when reading fails or the length does not match.
// The caller owns body; Upload neither closes it nor retries ambiguous writes.
func (c *Client) Upload(ctx context.Context, header *PutObjectHeader, body io.Reader, opts ...grpc.CallOption) (*PutObjectResponse, error) {
	if header == nil || header.ContentLength == nil || body == nil {
		return nil, status.Error(codes.InvalidArgument, "upload requires a header, content length and body")
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stream, err := c.PutObject(ctx, opts...)
	if err != nil {
		return nil, err
	}
	send := func(frame *PutObjectRequest) error {
		err := stream.Send(frame)
		if errors.Is(err, io.EOF) {
			// A rejected send reports EOF; receive the server's actual status
			// without sending FIN for an incomplete body.
			err = stream.RecvMsg(new(PutObjectResponse))
			if err == nil {
				err = status.Error(codes.Internal, "upload completed before the body was sent")
			}
		}
		return err
	}
	if err := send(&PutObjectRequest{Frame: &PutObjectRequest_Header{Header: header}}); err != nil {
		return nil, err
	}
	buffer := make([]byte, 64*1024)
	for remaining := header.GetContentLength(); remaining > 0; {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		n, err := io.ReadFull(body, buffer[:min(uint64(len(buffer)), remaining)])
		if err != nil {
			return nil, fmt.Errorf("read upload body: %w", err)
		}
		if err := send(&PutObjectRequest{Frame: &PutObjectRequest_Data{Data: buffer[:n]}}); err != nil {
			return nil, err
		}
		remaining -= uint64(n)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	// EOF, rather than just the declared byte count, gates signed FIN.
	if n, err := io.ReadFull(body, buffer[:1]); n != 0 {
		return nil, status.Error(codes.InvalidArgument, "upload body exceeds content length")
	} else if err != io.EOF {
		return nil, fmt.Errorf("read upload body: %w", err)
	}
	return stream.CloseAndRecv()
}

// DownloadOutput contains object metadata and a streaming body. Callers must
// close Body to release an unfinished download, and read it to EOF to verify
// the declared length and final RPC status. Close does not verify unread data.
type DownloadOutput struct {
	Metadata *ObjectMetadata
	Body     io.ReadCloser
}

// Download opens an object or range as an io.ReadCloser. It checks the returned
// object identity before exposing the body; Body validates framing, length and
// terminal status while reading. Memory use is bounded by the protocol chunk
// limit, regardless of object size.
func (c *Client) Download(ctx context.Context, request *GetObjectRequest, opts ...grpc.CallOption) (*DownloadOutput, error) {
	if request.GetObject() == nil {
		return nil, status.Error(codes.InvalidArgument, "download requires an object")
	}
	ctx, cancel := context.WithCancel(ctx)
	stream, err := c.GetObject(ctx, request, opts...)
	if err != nil {
		cancel()
		return nil, err
	}
	first, err := stream.Recv()
	if err != nil {
		cancel()
		return nil, err
	}
	metadata := first.GetMetadata()
	if metadata.GetObject() == nil || metadata.GetObject().GetBucket() != request.Object.Bucket || metadata.GetObject().GetKey() != request.Object.Key {
		cancel()
		return nil, status.Error(codes.DataLoss, "unexpected download object metadata")
	}
	return &DownloadOutput{Metadata: metadata, Body: &downloadBody{recv: stream.Recv, cancel: cancel}}, nil
}

type downloadBody struct {
	recv     func() (*GetObjectResponse, error)
	cancel   context.CancelFunc
	pending  []byte
	terminal error
}

func (r *downloadBody) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	for len(r.pending) == 0 {
		if r.terminal != nil {
			return 0, r.terminal
		}
		frame, err := r.recv()
		if err != nil {
			r.terminal = err
			r.cancel()
			return 0, err
		}
		r.pending = frame.GetData()
	}
	n := copy(p, r.pending)
	r.pending = r.pending[n:]
	return n, nil
}

func (r *downloadBody) Close() error {
	r.cancel()
	r.pending = nil
	r.terminal = io.ErrClosedPipe
	return nil
}
