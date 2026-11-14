package publiccli

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"path/filepath"
	"strings"
	"testing"

	iamv1 "go.motiveiq.dev/platform/iam/api/v1"
	motiveiq "go.motiveiq.dev/platform/iam/sdk"
	s3v1 "go.motiveiq.dev/platform/s3/api/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/proto"
)

type s3WireServer struct {
	s3v1.UnimplementedDataPlaneServer
	s3v1.UnimplementedControlPlaneServer
	frames                        []*iamv1.SignedStreamFrame
	upload                        []byte
	dataMetadata, controlMetadata metadata.MD
}

func (s *s3WireServer) ListBuckets(ctx context.Context, _ *s3v1.ListBucketsRequest) (*s3v1.ListBucketsResponse, error) {
	s.controlMetadata, _ = metadata.FromIncomingContext(ctx)
	return &s3v1.ListBucketsResponse{}, nil
}
func (s *s3WireServer) HeadObject(ctx context.Context, q *s3v1.HeadObjectRequest) (*s3v1.HeadObjectResponse, error) {
	s.dataMetadata, _ = metadata.FromIncomingContext(ctx)
	return &s3v1.HeadObjectResponse{Metadata: &s3v1.ObjectMetadata{Object: q.Object, ContentLength: uint64(len(s.upload)), Etag: "etag"}}, nil
}
func (s *s3WireServer) GetObject(q *s3v1.GetObjectRequest, stream grpc.ServerStreamingServer[s3v1.GetObjectResponse]) error {
	if err := stream.Send(&s3v1.GetObjectResponse{Frame: &s3v1.GetObjectResponse_Metadata{Metadata: &s3v1.ObjectMetadata{Object: q.Object, ContentLength: uint64(len(s.upload)), Etag: "etag"}}}); err != nil {
		return err
	}
	for data := s.upload; len(data) > 0; {
		n := min(len(data), 64*1024)
		if err := stream.Send(&s3v1.GetObjectResponse{Frame: &s3v1.GetObjectResponse_Data{Data: data[:n]}}); err != nil {
			return err
		}
		data = data[n:]
	}
	return nil
}
func (s *s3WireServer) PutObject(stream grpc.ClientStreamingServer[iamv1.SignedStreamFrame, s3v1.PutObjectResponse]) error {
	var header s3v1.PutObjectHeader
	for {
		frame, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		s.frames = append(s.frames, frame)
		var body iamv1.RequestStreamFrameBody
		if err := proto.Unmarshal(frame.Body, &body); err != nil {
			return err
		}
		if open := body.GetOpen(); open != nil {
			if err := proto.Unmarshal(open.RequestBytes, &header); err != nil {
				return err
			}
		}
		if data := body.GetData(); len(data) > 0 {
			var q s3v1.PutObjectRequest
			if err := proto.Unmarshal(data, &q); err != nil {
				return err
			}
			s.upload = append(s.upload, q.GetData()...)
		}
	}
	if uint64(len(s.upload)) != header.GetContentLength() {
		return fmt.Errorf("incomplete body")
	}
	return stream.SendAndClose(&s3v1.PutObjectResponse{})
}

// Exercise CLI -> shared config / STS -> S3 facade -> actual gRPC wire. Core
// verifier conformance lives in the IAM SDK; this pins that IQ uses that facade.
func TestIQS3UsesSignedStreamingFacade(t *testing.T) {
	listener := bufconn.Listen(1 << 20)
	server := grpc.NewServer()
	sts := new(proofConfigTestServer)
	s3 := new(s3WireServer)
	iamv1.RegisterSTSServer(server, sts)
	s3v1.RegisterDataPlaneServer(server, s3)
	s3v1.RegisterControlPlaneServer(server, s3)
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { server.Stop(); _ = listener.Close() })
	c := NewCommand()
	out, errout := new(bytes.Buffer), new(bytes.Buffer)
	c.Stdout = out
	c.Stderr = errout
	cacheDirectory := filepath.Join(t.TempDir(), "sts-cache")
	c.Env = func(name string) string {
		if name == IAMEndpointEnv {
			return "passthrough:///bufconn"
		}
		if name == IAMSessionCacheDirEnv {
			return cacheDirectory
		}
		if name == S3EndpointEnv {
			return "https://127.0.0.1"
		}
		return ""
	}
	useTestIdentity(c, func(context.Context) (string, error) { return "web-identity", nil })
	dialer := func(context.Context, string) (net.Conn, error) { return listener.Dial() }
	c.LoadSDKConfig = func(ctx context.Context, role string) (*motiveiq.Config, error) {
		return c.loadSDKConfigWithOptions(ctx, role, motiveiq.WithTransportCredentials(insecure.NewCredentials()), motiveiq.WithClientTransportCredentials(insecure.NewCredentials()), motiveiq.WithDialOptions(grpc.WithContextDialer(dialer)), motiveiq.WithClientDialOptions(grpc.WithContextDialer(dialer)))
	}
	payload := bytes.Repeat([]byte("signed upload"), 15000)
	name := filepath.Join(t.TempDir(), "source")
	writeS3File(t, name, payload)
	s3RunTest(t, c, errout, "cp", name, "s3://assets/object", "--endpoint-url", "https://localhost")
	if !bytes.Equal(s3.upload, payload) || len(s3.frames) < 4 {
		t.Fatal("missing streaming data")
	}
	parent := make([]byte, 32)
	var streamID []byte
	var count, size uint64
	var key []byte
	for i, frame := range s3.frames {
		var body iamv1.RequestStreamFrameBody
		if err := proto.Unmarshal(frame.Body, &body); err != nil {
			t.Fatal(err)
		}
		if body.Profile != "motiveiq-grpc-upload-v1" || body.Sequence != uint64(i) || !bytes.Equal(body.PreviousFrameSha256, parent) {
			t.Fatalf("broken frame %d chain", i)
		}
		if i == 0 {
			streamID = body.StreamId
			if frame.SessionToken != "session-token" || body.GetOpen() == nil {
				t.Fatal("missing authenticated OPEN")
			}
		} else if frame.SessionToken != "" {
			t.Fatal("session repeated after OPEN")
		}
		if !bytes.Equal(streamID, body.StreamId) {
			t.Fatal("stream ID changed")
		}
		parts := strings.Split(frame.Proof, ".")
		if len(parts) != 3 {
			t.Fatal("missing frame proof")
		}
		rawHeader, _ := base64.RawURLEncoding.DecodeString(parts[0])
		var header struct {
			JWK struct {
				X string `json:"x"`
			} `json:"jwk"`
		}
		if err := json.Unmarshal(rawHeader, &header); err != nil {
			t.Fatal(err)
		}
		public, _ := base64.RawURLEncoding.DecodeString(header.JWK.X)
		if i == 0 {
			key = public
		}
		signature, _ := base64.RawURLEncoding.DecodeString(parts[2])
		if !bytes.Equal(public, key) || !ed25519.Verify(public, []byte(parts[0]+"."+parts[1]), signature) {
			t.Fatal("invalid per-frame signature")
		}
		rawClaims, _ := base64.RawURLEncoding.DecodeString(parts[1])
		var claims struct {
			Version   int    `json:"mqi_v"`
			Transport string `json:"mqi_transport"`
			Hash      string `json:"mqi_request_hash"`
			Target    string `json:"htu"`
		}
		if err := json.Unmarshal(rawClaims, &claims); err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(frame.Body)
		if claims.Version != 3 || claims.Transport != "grpc-upload-v1" || claims.Hash != base64.RawURLEncoding.EncodeToString(digest[:]) || claims.Target != s3v1.ServiceOrigin+s3v1.DataPlane_PutObject_FullMethodName {
			t.Fatal("incorrect frame proof binding")
		}
		if data := body.GetData(); len(data) > 0 {
			count++
			size += uint64(len(data))
		}
		if i == len(s3.frames)-1 {
			fin := body.GetFinish()
			if fin == nil || fin.DataMessageCount != count || fin.DataPayloadBytes != size {
				t.Fatal("missing authenticated FIN")
			}
		}
		hash := sha256.New()
		hash.Write([]byte("motiveiq-grpc-upload-frame-v1\x00"))
		var length [4]byte
		binary.BigEndian.PutUint32(length[:], uint32(len(frame.Body)))
		hash.Write(length[:])
		hash.Write(frame.Body)
		binary.BigEndian.PutUint32(length[:], uint32(len(frame.Proof)))
		hash.Write(length[:])
		hash.Write([]byte(frame.Proof))
		parent = hash.Sum(nil)
	}
	out.Reset()
	s3RunTest(t, c, errout, "cp", "s3://assets/object", "-")
	if !bytes.Equal(out.Bytes(), payload) {
		t.Fatal("wire download mismatch")
	}
	assertProofMetadata(t, s3.dataMetadata, "DPoP session-token", s3v1.DataPlane_HeadObject_FullMethodName, s3v1.ServiceOrigin)
	s3RunTest(t, c, errout, "ls")
	assertProofMetadata(t, s3.controlMetadata, "DPoP session-token", s3v1.ControlPlane_ListBuckets_FullMethodName, s3v1.ServiceOrigin)
}
