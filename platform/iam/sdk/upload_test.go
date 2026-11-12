package motiveiq

import (
	"context"
	"testing"
	"time"

	iamv1 "go.motiveiq.dev/platform/iam/api/v1"
	"go.motiveiq.dev/platform/iam/internal/proof"
	"go.motiveiq.dev/platform/iam/internal/proofstream"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/emptypb"
)

type uploadRecordingStream struct {
	grpc.ClientStream
	frames []*iamv1.SignedStreamFrame
}

func (s *uploadRecordingStream) SendMsg(message any) error {
	s.frames = append(s.frames, proto.Clone(message.(*iamv1.SignedStreamFrame)).(*iamv1.SignedStreamFrame))
	return nil
}
func (s *uploadRecordingStream) CloseSend() error { return nil }

// Refresh must never change the token/key of an upload already in progress.
// Verify the complete wire chain with the original key after replacing the
// provider's generation, independently of the private server middleware.
func TestSignedUploadFreezesCredentialGeneration(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	signer, err := proof.GenerateSigner(nil)
	if err != nil {
		t.Fatal(err)
	}
	creds := staticHTTPTestCredentials(now, signer)
	original := creds.generation
	cfg, err := LoadDefaultConfig(context.Background(), WithClock(func() time.Time { return now }))
	if err != nil {
		t.Fatal(err)
	}
	defer cfg.Close()
	const method = "/test.Upload/Put"
	ctx := context.WithValue(context.Background(), signedUploadMethodKey{}, method)
	recorded := new(uploadRecordingStream)
	stream, err := cfg.clientRuntime.proofStreamInterceptor("upload", proofTestOrigin, creds, RequestProofOptions{})(ctx, &grpc.StreamDesc{ClientStreams: true}, nil, method, func(context.Context, *grpc.StreamDesc, *grpc.ClientConn, string, ...grpc.CallOption) (grpc.ClientStream, error) {
		return recorded, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if err = stream.SendMsg(&emptypb.Empty{}); err != nil {
		t.Fatal(err)
	}
	replacement, err := proof.GenerateSigner(nil)
	if err != nil {
		t.Fatal(err)
	}
	creds.mu.Lock()
	creds.generation = &credentialGeneration{token: "different-token", signer: replacement, expiresAt: original.expiresAt, refreshAt: original.refreshAt}
	creds.mu.Unlock()
	if err = stream.SendMsg(&emptypb.Empty{}); err != nil {
		t.Fatal(err)
	}
	if err = stream.CloseSend(); err != nil {
		t.Fatal(err)
	}
	if len(recorded.frames) != 3 {
		t.Fatalf("frames = %d, want OPEN/DATA/FIN", len(recorded.frames))
	}
	first := recorded.frames[0]
	if first.SessionToken != original.token {
		t.Fatal("OPEN used a different token")
	}
	decoder, _, _, err := proofstream.NewDecoder(first, proof.Binding{Operation: method, TargetURI: proofTestOrigin + method}, signer.Thumbprint(), original.expiresAt, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	for i, frame := range recorded.frames[1:] {
		_, finished, err := decoder.Next(frame)
		if err != nil || finished != (i == 1) {
			t.Fatalf("frame %d: finished=%t, error=%v", i+1, finished, err)
		}
	}
}
