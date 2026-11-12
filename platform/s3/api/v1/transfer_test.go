package s3v1

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

type transferConfig struct {
	grpc.ClientConnInterface
	upload      *transferUpload
	download    *transferDownload
	getContext  context.Context
	streamError error
}

func (f *transferConfig) GRPCClientConn(string, string, string, string) grpc.ClientConnInterface {
	return f
}
func (f *transferConfig) SignedUploadClientStream(ctx context.Context, key, endpoint, origin, override, method string, _ ...grpc.CallOption) (grpc.ClientStream, error) {
	if key != ServiceKey || origin != ServiceOrigin || method != DataPlane_PutObject_FullMethodName {
		return nil, errors.New("wrong proof profile")
	}
	f.upload.ctx = ctx
	return f.upload, f.streamError
}
func (f *transferConfig) NewStream(ctx context.Context, _ *grpc.StreamDesc, method string, _ ...grpc.CallOption) (grpc.ClientStream, error) {
	if method != DataPlane_GetObject_FullMethodName {
		return nil, errors.New("unexpected unsigned upload")
	}
	f.getContext = ctx
	return f.download, f.streamError
}

type transferUpload struct {
	grpc.ClientStream
	ctx        context.Context
	header     *PutObjectHeader
	data       []byte
	chunks     int
	finished   bool
	sendError  error
	finalError error
}

func (u *transferUpload) SendMsg(m any) error {
	if u.sendError != nil {
		return u.sendError
	}
	switch m := m.(type) {
	case *PutObjectHeader:
		u.header = proto.Clone(m).(*PutObjectHeader)
	case *PutObjectRequest:
		if len(m.GetData()) > 64*1024 {
			return errors.New("chunk too large")
		}
		u.data = append(u.data, m.GetData()...)
		u.chunks++
	default:
		return errors.New("unexpected frame")
	}
	return nil
}
func (u *transferUpload) CloseSend() error { u.finished = true; return nil }
func (u *transferUpload) RecvMsg(m any) error {
	m.(*PutObjectResponse).Metadata = &ObjectMetadata{Etag: "etag"}
	return u.finalError
}

type failingReader struct{ err error }

func (r failingReader) Read([]byte) (int, error) { return 0, r.err }

func TestUploadLengthAndCompletion(t *testing.T) {
	body := strings.Repeat("x", 130000)
	readError := errors.New("source failed")
	for _, tc := range []struct {
		name     string
		body     io.Reader
		size     uint64
		err      error
		wantBody string
		finished bool
	}{
		{"complete", strings.NewReader(body), uint64(len(body)), nil, body, true},
		{"empty", strings.NewReader(""), 0, nil, "", true},
		{"short", strings.NewReader(body), uint64(len(body)) + 1, io.ErrUnexpectedEOF, "", false},
		{"excess", strings.NewReader(body), uint64(len(body)) - 1, nil, "", false},
		{"excess empty", strings.NewReader("x"), 0, nil, "", false},
		{"source failure", failingReader{readError}, 1, readError, "", false},
		{"failure at EOF", io.MultiReader(strings.NewReader(body), failingReader{readError}), uint64(len(body)), readError, "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			u := &transferUpload{}
			c := NewFromConfig(&transferConfig{upload: u})
			header := &PutObjectHeader{Bucket: "bucket", Key: "key", ContentLength: &tc.size, ContentType: "text/plain", Metadata: map[string]string{"label": "value"}, Conditions: &ObjectConditions{IfNoneMatch: "*"}}
			out, err := c.Upload(context.Background(), header, tc.body)
			if (err == nil) != tc.finished || (tc.err != nil && !errors.Is(err, tc.err)) {
				t.Fatalf("unexpected outcome: %v", err)
			}
			if u.ctx.Err() == nil || u.finished != tc.finished {
				t.Fatalf("stream lifetime: canceled=%v, finished=%v", u.ctx.Err(), u.finished)
			}
			if !proto.Equal(u.header, header) {
				t.Fatal("upload changed metadata or conditions")
			}
			if tc.finished && (string(u.data) != tc.wantBody || out.GetMetadata().GetEtag() != "etag") {
				t.Fatal("changed uploaded body or response")
			}
			if tc.name == "complete" && u.chunks != 2 {
				t.Fatalf("want 2 bounded chunks, got %d", u.chunks)
			}
		})
	}
}

func TestUploadPropagatesTransportErrors(t *testing.T) {
	for _, tc := range []struct {
		name      string
		streamErr error
		sendErr   error
		finalErr  error
		want      codes.Code
		finished  bool
	}{
		{"open failure", status.Error(codes.Unavailable, "open"), nil, nil, codes.Unavailable, false},
		{"send failure", nil, status.Error(codes.Canceled, "send"), nil, codes.Canceled, false},
		{"rejected send", nil, io.EOF, status.Error(codes.PermissionDenied, "denied"), codes.PermissionDenied, false},
		{"premature response", nil, io.EOF, nil, codes.Internal, false},
		{"already exists", nil, nil, status.Error(codes.AlreadyExists, "exists"), codes.AlreadyExists, true},
		{"lost response", nil, nil, status.Error(codes.Unavailable, "lost"), codes.Unavailable, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			u := &transferUpload{sendError: tc.sendErr, finalError: tc.finalErr}
			c := NewFromConfig(&transferConfig{upload: u, streamError: tc.streamErr})
			_, err := c.Upload(context.Background(), &PutObjectHeader{ContentLength: proto.Uint64(4)}, strings.NewReader("body"))
			if status.Code(err) != tc.want || u.finished != tc.finished || u.ctx.Err() == nil {
				t.Fatalf("err=%v, finished=%v, canceled=%v", err, u.finished, u.ctx.Err())
			}
		})
	}
}

func TestUploadRequiresLengthAndBody(t *testing.T) {
	c := NewFromConfig(&transferConfig{})
	for _, header := range []*PutObjectHeader{nil, {}} {
		if _, err := c.Upload(context.Background(), header, strings.NewReader("")); status.Code(err) != codes.InvalidArgument {
			t.Fatalf("accepted absent content length: %v", err)
		}
	}
	if _, err := c.Upload(context.Background(), &PutObjectHeader{ContentLength: proto.Uint64(0)}, nil); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("accepted nil body: %v", err)
	}
}

type transferDownload struct {
	downloadFixture
	request *GetObjectRequest
}

func (d *transferDownload) SendMsg(m any) error {
	d.request = proto.Clone(m.(*GetObjectRequest)).(*GetObjectRequest)
	return nil
}
func (d *transferDownload) CloseSend() error { return nil }
func transferMetadata(size uint64) *GetObjectResponse {
	return &GetObjectResponse{Frame: &GetObjectResponse_Metadata{Metadata: &ObjectMetadata{Object: &ObjectRef{Bucket: "bucket", Key: "key"}, ContentLength: size, ContentType: "text/plain"}}}
}
func transferData(b string) *GetObjectResponse {
	return &GetObjectResponse{Frame: &GetObjectResponse_Data{Data: []byte(b)}}
}
func TestDownloadBodyValidation(t *testing.T) {
	wrongObject := transferMetadata(0)
	wrongObject.GetMetadata().Object.Key = "wrong"
	for _, tc := range []struct {
		name     string
		frames   []*GetObjectResponse
		terminal error
		want     codes.Code
		body     string
	}{
		{"complete", []*GetObjectResponse{transferMetadata(4), transferData("body")}, io.EOF, codes.OK, "body"},
		{"empty", []*GetObjectResponse{transferMetadata(0)}, io.EOF, codes.OK, ""},
		{"short", []*GetObjectResponse{transferMetadata(5), transferData("body")}, io.EOF, codes.DataLoss, ""},
		{"excess", []*GetObjectResponse{transferMetadata(3), transferData("body")}, io.EOF, codes.DataLoss, ""},
		{"missing metadata", []*GetObjectResponse{transferData("body")}, io.EOF, codes.DataLoss, ""},
		{"duplicate metadata", []*GetObjectResponse{transferMetadata(4), transferMetadata(4), transferData("body")}, io.EOF, codes.DataLoss, ""},
		{"wrong object", []*GetObjectResponse{wrongObject}, io.EOF, codes.DataLoss, ""},
		{"late failure", []*GetObjectResponse{transferMetadata(4), transferData("body")}, status.Error(codes.Unavailable, "lost"), codes.Unavailable, ""},
		{"missing", nil, status.Error(codes.NotFound, "missing"), codes.NotFound, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := &transferDownload{downloadFixture: downloadFixture{messages: tc.frames, err: tc.terminal}}
			f := &transferConfig{download: d}
			out, err := NewFromConfig(f).Download(context.Background(), &GetObjectRequest{Object: &ObjectRef{Bucket: "bucket", Key: "key"}})
			if err == nil {
				defer out.Body.Close()
				if out.Metadata.GetContentType() != "text/plain" {
					t.Fatal("lost object metadata")
				}
				var b []byte
				b, err = io.ReadAll(out.Body)
				if tc.want == codes.OK && string(b) != tc.body {
					t.Fatal("bytes changed")
				}
			}
			if status.Code(err) != tc.want || f.getContext.Err() == nil {
				t.Fatalf("err=%v, canceled=%v", err, f.getContext.Err())
			}
		})
	}
}

func TestDownloadRangeAndClose(t *testing.T) {
	metadata := transferMetadata(4)
	metadata.GetMetadata().ContentRange = "bytes 2-5/8"
	d := &transferDownload{downloadFixture: downloadFixture{messages: []*GetObjectResponse{metadata, transferData("body")}, err: io.EOF}}
	f := &transferConfig{download: d}
	request := &GetObjectRequest{Object: &ObjectRef{Bucket: "bucket", Key: "key"}, Range: &ByteRange{Start: 2, EndInclusive: proto.Uint64(5)}, Conditions: &ObjectConditions{IfMatch: "etag"}}
	out, err := NewFromConfig(f).Download(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if !proto.Equal(d.request, request) || out.Metadata.GetContentRange() != "bytes 2-5/8" {
		t.Fatal("lost range or conditions")
	}
	b := make([]byte, 1)
	if _, err := out.Body.Read(b); err != nil || string(b) != "b" {
		t.Fatalf("partial read: %q, %v", b, err)
	}
	if f.getContext.Err() != nil {
		t.Fatal("download canceled before close")
	}
	out.Body.Close()
	out.Body.Close()
	if _, err := out.Body.Read(b); !errors.Is(err, io.ErrClosedPipe) || f.getContext.Err() == nil {
		t.Fatalf("close left pending bytes or leaked stream: %v", err)
	}
}

func TestDownloadOpenErrors(t *testing.T) {
	f := &transferConfig{streamError: status.Error(codes.Unavailable, "open")}
	c := NewFromConfig(f)
	if _, err := c.Download(context.Background(), &GetObjectRequest{Object: &ObjectRef{Bucket: "bucket", Key: "key"}}); status.Code(err) != codes.Unavailable || f.getContext.Err() == nil {
		t.Fatalf("open error or cancellation lost: %v", err)
	}
	for _, request := range []*GetObjectRequest{nil, {}} {
		if _, err := c.Download(context.Background(), request); status.Code(err) != codes.InvalidArgument {
			t.Fatalf("accepted absent object: %v", err)
		}
	}
}
