package iamv1

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
	method  string
	request any
	options int
}

func (c *recordingConn) Invoke(_ context.Context, method string, args, reply any, opts ...grpc.CallOption) error {
	c.method = method
	c.request = args
	c.options = len(opts)
	switch response := reply.(type) {
	case *ListRolesResponse:
		response.Roles = []*Role{{Name: "human"}}
	case *GetCallerIdentityResponse:
		response.SessionId = "session_1"
	default:
		panic("unexpected response type")
	}
	return nil
}

func (*recordingConn) NewStream(context.Context, *grpc.StreamDesc, string, ...grpc.CallOption) (grpc.ClientStream, error) {
	panic("unexpected stream")
}

func TestNewFromConfigUsesServiceProfileAndGeneratedClient(t *testing.T) {
	conn := &recordingConn{}
	cfg := &recordingConfig{conn: conn}
	client := NewFromConfig(cfg)

	request := &ListRolesRequest{}
	response, err := client.ListRoles(context.Background(), request, grpc.WaitForReady(true))
	if err != nil {
		t.Fatalf("ListRoles: %v", err)
	}
	if len(response.GetRoles()) != 1 || response.GetRoles()[0].GetName() != "human" {
		t.Fatalf("roles = %v", response.GetRoles())
	}
	if cfg.serviceKey != ServiceKey || cfg.endpoint != defaultEndpoint || cfg.origin != ServiceOrigin || cfg.endpointOver != "" {
		t.Fatalf("config call = (%q, %q, %q, %q)", cfg.serviceKey, cfg.endpoint, cfg.origin, cfg.endpointOver)
	}
	if conn.method != IAM_ListRoles_FullMethodName || conn.request != request || conn.options != 2 {
		t.Fatalf("Invoke = method %q request %p options %d", conn.method, conn.request, conn.options)
	}
}

func TestNewSTSFromConfigUsesDistinctServiceProfileAndGeneratedClient(t *testing.T) {
	conn := &recordingConn{}
	cfg := &recordingConfig{conn: conn}
	client := NewSTSFromConfig(cfg)

	request := &GetCallerIdentityRequest{}
	response, err := client.GetCallerIdentity(context.Background(), request, grpc.WaitForReady(true))
	if err != nil {
		t.Fatalf("GetCallerIdentity: %v", err)
	}
	if response.GetSessionId() != "session_1" {
		t.Fatalf("session ID = %q", response.GetSessionId())
	}
	if cfg.serviceKey != STSServiceKey || cfg.endpoint != defaultEndpoint || cfg.origin != STSServiceOrigin || cfg.endpointOver != "" {
		t.Fatalf("config call = (%q, %q, %q, %q)", cfg.serviceKey, cfg.endpoint, cfg.origin, cfg.endpointOver)
	}
	if conn.method != STS_GetCallerIdentity_FullMethodName || conn.request != request || conn.options != 2 {
		t.Fatalf("Invoke = method %q request %p options %d", conn.method, conn.request, conn.options)
	}
}

func TestIAMClientsApplyTrimmedLocalEndpointOverride(t *testing.T) {
	tests := []struct {
		name string
		new  func(*recordingConfig)
	}{
		{"IAM", func(cfg *recordingConfig) {
			_ = NewFromConfig(cfg, func(options *ClientOptions) { options.BaseEndpoint = "  dns:///iam.test:8443  " })
		}},
		{"STS", func(cfg *recordingConfig) {
			_ = NewSTSFromConfig(cfg, func(options *ClientOptions) {
				options.BaseEndpoint = "  dns:///iam.test:8443  "
			})
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cfg := &recordingConfig{conn: &recordingConn{}}
			test.new(cfg)
			if cfg.endpointOver != "dns:///iam.test:8443" {
				t.Fatalf("endpoint override = %q", cfg.endpointOver)
			}
		})
	}
}
