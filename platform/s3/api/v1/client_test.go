package s3v1

import (
	"context"
	"testing"

	"google.golang.org/grpc"
)

type recordingConfig struct {
	conn                                       grpc.ClientConnInterface
	serviceKey, endpoint, origin, endpointOver string
}

func (c *recordingConfig) GRPCClientConn(serviceKey, defaultEndpoint, defaultOrigin, endpointOverride string) grpc.ClientConnInterface {
	c.serviceKey = serviceKey
	c.endpoint = defaultEndpoint
	c.origin = defaultOrigin
	c.endpointOver = endpointOverride
	return c.conn
}

type recordingConn struct {
	method string
}

func (c *recordingConn) Invoke(_ context.Context, method string, _, reply any, _ ...grpc.CallOption) error {
	c.method = method
	switch response := reply.(type) {
	case *ListBucketsResponse:
		response.Buckets = []*Bucket{{Name: "global-bucket"}}
	case *HeadBucketResponse:
		response.Bucket = &Bucket{Name: "global-bucket"}
	}
	return nil
}

func (*recordingConn) NewStream(context.Context, *grpc.StreamDesc, string, ...grpc.CallOption) (grpc.ClientStream, error) {
	panic("unexpected stream")
}

func TestNewFromConfigUsesServiceProfileAndGeneratedClient(t *testing.T) {
	conn := &recordingConn{}
	cfg := &recordingConfig{conn: conn}
	client := NewControlPlaneFromConfig(cfg, func(options *ClientOptions) {
		options.BaseEndpoint = "  dns:///s3.test:443  "
	})

	response, err := client.ListBuckets(context.Background(), &ListBucketsRequest{})
	if err != nil {
		t.Fatalf("ListBuckets: %v", err)
	}
	if len(response.GetBuckets()) != 1 || response.GetBuckets()[0].GetName() != "global-bucket" {
		t.Fatalf("buckets = %v", response.GetBuckets())
	}
	if cfg.serviceKey != ControlPlaneServiceKey || cfg.endpoint != "dns:///blob.platform.motiveiq.net:443" || cfg.origin != ControlPlaneServiceOrigin || cfg.endpointOver != "dns:///s3.test:443" {
		t.Fatalf("config call = (%q, %q, %q, %q)", cfg.serviceKey, cfg.endpoint, cfg.origin, cfg.endpointOver)
	}
	if conn.method != ControlPlane_ListBuckets_FullMethodName {
		t.Fatalf("Invoke method = %q", conn.method)
	}
}

func TestDataAndControlShareOriginButKeepDistinctProfilesAndMethods(t *testing.T) {
	conn := &recordingConn{}
	cfg := &recordingConfig{conn: conn}
	data := NewDataPlaneFromConfig(cfg)
	if cfg.serviceKey != ServiceKey || cfg.endpoint != "dns:///blob.platform.motiveiq.net:443" || cfg.origin != "https://blob.platform.motiveiq.net" {
		t.Fatalf("data profile: %+v", cfg)
	}
	if _, err := data.HeadBucket(context.Background(), &HeadBucketRequest{}); err != nil {
		t.Fatal(err)
	}
	if conn.method != "/motiveiq.s3.v1.DataPlane/HeadBucket" {
		t.Fatalf("data method: %s", conn.method)
	}
	dataOrigin := cfg.origin
	control := NewControlPlaneFromConfig(cfg)
	if cfg.serviceKey != ControlPlaneServiceKey || cfg.serviceKey == ServiceKey || cfg.endpoint != "dns:///blob.platform.motiveiq.net:443" || cfg.origin != dataOrigin {
		t.Fatalf("control profile: %+v", cfg)
	}
	if _, err := control.ListBuckets(context.Background(), &ListBucketsRequest{}); err != nil {
		t.Fatal(err)
	}
	if conn.method != "/motiveiq.s3.v1.ControlPlane/ListBuckets" {
		t.Fatalf("control method: %s", conn.method)
	}
}

func (*recordingConfig) SignedUploadClientStream(context.Context, string, string, string, string, string, ...grpc.CallOption) (grpc.ClientStream, error) {
	panic("unexpected upload")
}
