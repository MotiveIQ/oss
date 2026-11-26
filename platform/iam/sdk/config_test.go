package motiveiq

// LoadDefaultConfig contract tests: the environment-variable table, option
// precedence, and the per-component missing-configuration errors.

import (
	"context"
	"strings"
	"testing"
)

// clearEnv blanks the whole SDK environment contract so ambient variables
// cannot leak into a test.
func clearEnv(t *testing.T) {
	t.Helper()
	for _, key := range []string{
		EnvRoleURN, EnvWebIdentityTokenFile, EnvSTSEndpoint,
		EnvSTSProofOrigin,
		EnvSessionName,
	} {
		t.Setenv(key, "")
		t.Setenv("MOTIVEIQ_"+strings.TrimPrefix(key, "IQ_"), "")
	}
}

func TestLoadDefaultConfigFromEnvironment(t *testing.T) {
	t.Setenv(EnvRoleURN, testRoleURN)
	t.Setenv(EnvWebIdentityTokenFile, "/var/run/secrets/motiveiq/token")
	t.Setenv(EnvSTSEndpoint, "iam.iam-system.svc:8443")
	t.Setenv(EnvSTSProofOrigin, "https://sts.staging.example")
	t.Setenv(EnvSessionName, "reconciler-7f9d4")

	cfg, err := LoadDefaultConfig(context.Background())
	if err != nil {
		t.Fatalf("LoadDefaultConfig: %v", err)
	}
	if cfg.RoleURN != testRoleURN ||
		cfg.WebIdentityTokenFile != "/var/run/secrets/motiveiq/token" ||
		cfg.STSEndpoint != "iam.iam-system.svc:8443" ||
		cfg.STSProofOrigin != "https://sts.staging.example" ||
		cfg.sessionName != "reconciler-7f9d4" {
		t.Errorf("config = %+v (sessionName %q) does not match the environment", cfg, cfg.sessionName)
	}
}

func TestLoadDefaultConfigOptionsOverrideEnvironment(t *testing.T) {
	t.Setenv(EnvRoleURN, "urn:iq:iam:role/from-env")
	t.Setenv(EnvSTSEndpoint, "env-sts:1")
	t.Setenv(EnvSTSProofOrigin, "https://env-sts")
	t.Setenv(EnvSessionName, "env-pod-name")

	cfg, err := LoadDefaultConfig(context.Background(),
		WithRoleURN(testRoleURN),
		WithWebIdentityTokenFile("/opt/token"),
		WithSTSEndpoint("opt-sts:2"),
		WithSTSProofOrigin("https://opt-sts"),
		WithSessionName("opt-session"),
	)
	if err != nil {
		t.Fatalf("LoadDefaultConfig: %v", err)
	}
	if cfg.RoleURN != testRoleURN || cfg.WebIdentityTokenFile != "/opt/token" ||
		cfg.STSEndpoint != "opt-sts:2" ||
		cfg.STSProofOrigin != "https://opt-sts" ||
		cfg.sessionName != "opt-session" {
		t.Errorf("options did not take precedence: %+v (sessionName %q)", cfg, cfg.sessionName)
	}
}

func TestLoadDefaultConfigValidatesProofOriginIndependently(t *testing.T) {
	clearEnv(t)
	if _, err := LoadDefaultConfig(context.Background(),
		WithSTSProofOrigin("https://sts.example/proof"),
	); err == nil || !strings.Contains(err.Error(), EnvSTSProofOrigin) {
		t.Fatalf("LoadDefaultConfig error = %v, want invalid proof origin", err)
	}
}

func TestLoadDefaultConfigRejectsBadRoleURN(t *testing.T) {
	if _, err := LoadDefaultConfig(context.Background(), WithRoleURN("not-a-urn")); err == nil {
		t.Fatal("want error for a non-canonical role URN")
	}
}

func TestComponentConstructorsReportMissingConfig(t *testing.T) {
	clearEnv(t)
	cfg, err := LoadDefaultConfig(context.Background())
	if err != nil {
		t.Fatalf("LoadDefaultConfig: %v", err)
	}
	if _, err := cfg.Credentials(); err == nil || !strings.Contains(err.Error(), EnvRoleURN) {
		t.Errorf("Credentials() = %v, want an error naming %s", err, EnvRoleURN)
	}
}

func TestLegacyEnvironmentCompatibility(t *testing.T) {
	clearEnv(t)
	t.Setenv("MOTIVEIQ_ROLE_URN", testRoleURN)
	t.Setenv("MOTIVEIQ_WEB_IDENTITY_TOKEN_FILE", "/legacy-token")
	t.Setenv("MOTIVEIQ_STS_ENDPOINT", "legacy.example:443")
	t.Setenv("MOTIVEIQ_STS_PROOF_ORIGIN", "https://legacy-sts.example")
	t.Setenv("MOTIVEIQ_SESSION_NAME", "legacy-session")
	cfg, err := LoadDefaultConfig(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer cfg.Close()
	if cfg.RoleURN != testRoleURN || cfg.WebIdentityTokenFile != "/legacy-token" || cfg.STSEndpoint != "legacy.example:443" || cfg.STSProofOrigin != "https://legacy-sts.example" || cfg.sessionName != "legacy-session" {
		t.Fatalf("legacy environment was not discovered: %+v", cfg)
	}
	t.Setenv("IQ_ROLE_URN", "urn:iq:iam:role/canonical")
	t.Setenv("IQ_STS_ENDPOINT", "canonical.example:443")
	t.Setenv("IQ_STS_PROOF_ORIGIN", "https://canonical-sts.example")
	t.Setenv("IQ_SESSION_NAME", "canonical-session")
	cfg, err = LoadDefaultConfig(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer cfg.Close()
	if cfg.RoleURN != "urn:iq:iam:role/canonical" || cfg.WebIdentityTokenFile != "" || cfg.STSEndpoint != "canonical.example:443" || cfg.STSProofOrigin != "https://canonical-sts.example" || cfg.sessionName != "canonical-session" {
		t.Fatalf("canonical environment did not take precedence: %+v", cfg)
	}
	if _, err := cfg.Credentials(); err == nil {
		t.Fatal("partial IQ identity borrowed a legacy token")
	}
}

func TestLoadDefaultConfigRejectsLegacyRoleURN(t *testing.T) {
	clearEnv(t)
	t.Setenv(EnvRoleURN, "urn:motiveiq:iam:role/test")
	if _, err := LoadDefaultConfig(context.Background()); err == nil {
		t.Fatal("accepted a role URN in the retired namespace")
	}
}
