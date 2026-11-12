package cli

import (
	"testing"

	motiveiq "github.com/MotiveIQ/public/platform/iam/sdk"
)

func TestIdentityDiscovery(t *testing.T) {
	t.Setenv("SSL_CERT_FILE", "")
	t.Setenv(motiveiq.EnvRoleURN, "")
	t.Setenv(motiveiq.EnvWebIdentityTokenFile, "")
	t.Setenv(motiveiq.EnvSTSEndpoint, "")
	config, err := Load(t.Context(), "")
	if err != nil {
		t.Fatal(err)
	}
	if config.RoleURN != HumanRole || config.STSEndpoint != "iam.platform.motiveiq.net:443" {
		t.Fatal("human defaults changed")
	}
	config.Close()
	t.Setenv(motiveiq.EnvWebIdentityTokenFile, "/nonexistent/workload-token")
	config, err = Load(t.Context(), "")
	if err != nil {
		t.Fatal(err)
	}
	if config.RoleURN != "" {
		t.Fatal("workload silently assumed the human role")
	}
	if _, err := config.Credentials(); err == nil {
		t.Fatal("workload without a role was accepted")
	}
	config.Close()
	t.Setenv(motiveiq.EnvRoleURN, "urn:motiveiq:iam:role/automation")
	config, err = Load(t.Context(), "")
	if err != nil {
		t.Fatal(err)
	}
	if config.RoleURN != "urn:motiveiq:iam:role/automation" || config.WebIdentityTokenFile != "/nonexistent/workload-token" {
		t.Fatal("workload configuration lost")
	}
	config.Close()
	config, err = Load(t.Context(), "urn:motiveiq:iam:role/override")
	if err != nil {
		t.Fatal(err)
	}
	if config.RoleURN != "urn:motiveiq:iam:role/override" {
		t.Fatal("explicit role was ignored")
	}
	config.Close()
}
