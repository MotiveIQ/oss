package proof

import "testing"

func TestApplicationMetadataNamesByTransport(t *testing.T) {
	for _, tc := range []struct {
		name       string
		grpc, http bool
	}{
		{"resource-urn", true, true},
		{"content-type", false, true},
		{"user-agent", false, true},
		{"grpc-timeout", false, true},
		{"opaque-bin", false, true},
		{"host", true, false},
		{"content-digest", true, false},
		{"content-length", true, false},
		{"connection", true, false},
		{"transfer-encoding", true, false},
		{"trailer", true, false},
		{"upgrade", true, false},
		{"proxy-authorization", true, false},
		{"proxy-authenticate", true, false},
		{"te", false, false},
		{"authorization", false, false},
		{"dpop", false, false},
		{DelegationTokenMetadata, false, false},
		{DelegationTokenDigestMetadata, false, false},
		{"Content-Type", false, false},
		{"", false, false},
	} {
		for transport, allowed := range map[Transport]bool{TransportGRPC: tc.grpc, TransportHTTP: tc.http} {
			t.Run(string(transport)+"/"+tc.name, func(t *testing.T) {
				err := ValidateApplicationMetadataNames(transport, []string{tc.name})
				if (err == nil) != allowed {
					t.Fatalf("allowed=%t: %v", allowed, err)
				}
			})
		}
	}
	if err := ValidateApplicationMetadataNames(TransportHTTP, []string{"content-type", "content-type"}); err == nil {
		t.Fatal("duplicate singleton name accepted")
	}
	if err := ValidateApplicationMetadataNames("unknown", nil); err == nil {
		t.Fatal("unregistered transport accepted")
	}
}
