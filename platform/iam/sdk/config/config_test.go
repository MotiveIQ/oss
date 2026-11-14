package config

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pelletier/go-toml/v2"

	motiveiq "go.motiveiq.dev/platform/iam/sdk"
)

const testRole = "urn:motiveiq:iam:role/test"

func testResolver(t *testing.T) (Resolver, map[string]string) {
	t.Helper()
	env := map[string]string{"XDG_CONFIG_HOME": t.TempDir()}
	return Resolver{Env: func(key string) string { return env[key] }}, env
}

func writeConfig(t *testing.T, env map[string]string, config FileConfig) {
	t.Helper()
	path := filepath.Join(env["XDG_CONFIG_HOME"], "config.toml")
	data, err := toml.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	env[ConfigFileEnv] = path
}

func fileConfig(path string) FileConfig {
	return FileConfig{
		Profiles:           map[string]Profile{"default": {RoleURN: testRole, WebIdentitySource: "test"}, "production": {RoleURN: "urn:motiveiq:iam:role/production", WebIdentitySource: "test", STSEndpoint: "sts.example:443"}},
		WebIdentitySources: map[string]Source{"test": {Type: "file", Config: SourceConfig{"path": path}}},
	}
}

func TestResolutionPrecedence(t *testing.T) {
	r, env := testResolver(t)
	profileFile := filepath.Join(t.TempDir(), "profile-token")
	writeConfig(t, env, fileConfig(profileFile))
	env[RoleURNEnv] = "urn:motiveiq:iam:role/workload"
	env[WebIdentityTokenFileEnv] = filepath.Join(t.TempDir(), "workload-token")
	env[STSEndpointEnv] = "workload.example:443"
	identity, err := r.Resolve("")
	if err != nil || identity.RoleURN != env[RoleURNEnv] || identity.STSEndpoint != env[STSEndpointEnv] {
		t.Fatalf("environment selection: %+v, %v", identity, err)
	}
	env[ProfileEnv] = "production"
	identity, err = r.Resolve("")
	if err != nil || identity.RoleURN != "urn:motiveiq:iam:role/production" || identity.STSEndpoint != "sts.example:443" {
		t.Fatalf("named profile selection: %+v, %v", identity, err)
	}
	r.Profile = "default"
	identity, err = r.Resolve("urn:motiveiq:iam:role/override")
	if err != nil || identity.ProfileName != "default" || identity.RoleURN != "urn:motiveiq:iam:role/override" || identity.STSEndpoint != "" {
		t.Fatalf("explicit override: %+v, %v", identity, err)
	}
	// Resolve is lazy: neither missing token file has been read yet.
	if _, err := identity.Provider.RetrieveWebIdentityToken(t.Context()); err == nil {
		t.Fatal("missing selected file was ignored")
	}
}

func TestExplicitProfileOverridesWorkloadEnvironment(t *testing.T) {
	// Explicit profile selection pins identity even inside a workload. With
	// no profile selected, the same environment must work automatically.
	t.Setenv(motiveiq.EnvRoleURN, "urn:motiveiq:iam:role/ambient")
	t.Setenv(motiveiq.EnvWebIdentityTokenFile, "/ambient-token")
	t.Setenv(motiveiq.EnvSTSEndpoint, "ambient.invalid:443")
	t.Setenv(motiveiq.EnvSTSProofOrigin, "invalid ambient proof origin")
	t.Setenv(motiveiq.EnvSessionName, "ambient-session")
	t.Setenv("SSL_CERT_FILE", "")
	r, env := testResolver(t)
	for _, key := range []string{motiveiq.EnvRoleURN, motiveiq.EnvWebIdentityTokenFile, motiveiq.EnvSTSEndpoint} {
		env[key] = os.Getenv(key)
	}
	if identity, err := r.Resolve(""); err != nil || identity.RoleURN != "urn:motiveiq:iam:role/ambient" {
		t.Fatalf("workload was not discovered without a profile: %+v, %v", identity, err)
	}
	writeConfig(t, env, fileConfig("/configured-token"))
	r.Profile = "default"
	env[SessionNameEnv] = "cli-session"
	identity, err := r.Resolve("")
	if err != nil || identity.RoleURN != testRole || identity.SessionName != "cli-session" {
		t.Fatalf("CLI profile: %+v, %v", identity, err)
	}
	config, err := LoadIdentity(t.Context(), identity)
	if err != nil {
		t.Fatal(err)
	}
	defer config.Close()
	if config.RoleURN != testRole || config.STSEndpoint != DefaultSTSEndpoint || config.WebIdentityTokenFile != "" || config.STSProofOrigin != motiveiq.DefaultSTSProofOrigin {
		t.Fatal("CLI configuration inherited the SDK environment")
	}
}

func TestExplicitConfigurationNeverFallsBack(t *testing.T) {
	for _, scenario := range []string{"missing-profile", "missing-source", "unknown-provider", "missing-file", "malformed", "partial-environment"} {
		t.Run(scenario, func(t *testing.T) {
			r, env := testResolver(t)
			switch scenario {
			case "missing-profile":
				r.Profile = "missing"
			case "missing-source":
				config := fileConfig("/unused")
				config.WebIdentitySources = nil
				writeConfig(t, env, config)
			case "unknown-provider":
				config := fileConfig("/unused")
				config.WebIdentitySources["test"] = Source{Type: "missing"}
				writeConfig(t, env, config)
			case "missing-file":
				env[ConfigFileEnv] = filepath.Join(t.TempDir(), "absent")
			case "malformed":
				env[ConfigFileEnv] = filepath.Join(t.TempDir(), "bad")
				if err := os.WriteFile(env[ConfigFileEnv], []byte(`{"profiles":`), 0o600); err != nil {
					t.Fatal(err)
				}
			case "partial-environment":
				env[RoleURNEnv] = testRole
			}
			if _, err := r.Resolve(""); err == nil {
				t.Fatal("invalid selection fell back to defaults")
			}
		})
	}
	r, _ := testResolver(t)
	if _, err := r.Resolve(""); err == nil {
		t.Fatal("public resolver supplied an implicit identity")
	}
}

func TestFileRotationAndSourceFailure(t *testing.T) {
	r, env := testResolver(t)
	path := filepath.Join(t.TempDir(), "token")
	writeConfig(t, env, fileConfig(path))
	identity, err := r.Resolve("")
	if err != nil {
		t.Fatal(err)
	}
	for _, token := range []string{"first", "rotated"} {
		if err := os.WriteFile(path, []byte(token+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		got, err := identity.Provider.RetrieveWebIdentityToken(t.Context())
		if err != nil || got != token {
			t.Fatalf("rotation: %q, %v", got, err)
		}
	}
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := identity.Provider.RetrieveWebIdentityToken(t.Context()); err == nil {
		t.Fatal("empty token accepted")
	}
}

func TestTOMLProfilesAndStrictValidation(t *testing.T) {
	const document = `# Quoted names and comments are ordinary TOML.
[profiles."ci.production"]
role_urn = "urn:motiveiq:iam:role/test"
web_identity_source = "external"

[web_identity_sources.external]
type = "process"
[web_identity_sources.external.config]
command = ["/usr/bin/helper", "token"]
`
	for _, test := range []struct {
		name, data string
		valid      bool
	}{
		{"quoted-profile", document, true},
		{"JSON", `{"profiles":{}}`, false},
		{"syntax", document + "secret = [\"PRIVATE", false},
		{"unknown-profile-setting", strings.Replace(document, "role_urn =", "role =", 1), false},
		{"unknown-source-setting", document + "password = \"PRIVATE\"\n", false},
		{"duplicate-key", document + "command = [\"PRIVATE\"]\n", false},
		{"wrong-type", strings.Replace(document, `["/usr/bin/helper", "token"]`, `"PRIVATE"`, 1), false},
	} {
		t.Run(test.name, func(t *testing.T) {
			r, env := testResolver(t)
			r.Profile = "ci.production"
			env[ConfigFileEnv] = filepath.Join(t.TempDir(), "config.toml")
			if err := os.WriteFile(env[ConfigFileEnv], []byte(test.data), 0o600); err != nil {
				t.Fatal(err)
			}
			identity, err := r.Resolve("")
			if (err == nil) != test.valid {
				t.Fatalf("valid=%v, error=%v", test.valid, err)
			}
			if err != nil && strings.Contains(err.Error(), "PRIVATE") {
				t.Fatal("configuration error included source content")
			}
			if test.valid && (identity.ProfileName != "ci.production" || identity.RoleURN != testRole) {
				t.Fatalf("incorrect TOML profile: %+v", identity)
			}
		})
	}
}

func TestRegisteredProviderRemainsLazyAndFailsClosed(t *testing.T) {
	r, env := testResolver(t)
	calls := 0
	failure := errors.New("external authentication expired")
	r.ProviderFactories = map[string]ProviderFactory{"custom": func(SourceConfig) (motiveiq.WebIdentityTokenProvider, error) {
		return motiveiq.WebIdentityTokenProviderFunc(func(context.Context) (string, error) { calls++; return "", failure }), nil
	}}
	config := fileConfig("/unused")
	config.WebIdentitySources["test"] = Source{Type: "custom", Config: SourceConfig{}}
	writeConfig(t, env, config)
	identity, err := r.Resolve("")
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("SSL_CERT_FILE", "")
	sdkConfig, err := LoadIdentity(t.Context(), identity)
	if err != nil {
		t.Fatal(err)
	}
	defer sdkConfig.Close()
	if calls != 0 {
		t.Fatal("configuration retrieved credentials")
	}
	creds, err := sdkConfig.Credentials()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := creds.Token(t.Context()); !errors.Is(err, failure) || calls != 1 {
		t.Fatalf("source failure changed: %v; calls=%d", err, calls)
	}
}

// The test executable doubles as a portable helper, without a shell or fixtures
// containing credentials. The separator keeps these modes out of ordinary tests.
func TestProcessHelper(t *testing.T) {
	if len(os.Args) < 3 || os.Args[len(os.Args)-2] != "--" {
		return
	}
	switch os.Args[len(os.Args)-1] {
	case "ok":
		fmt.Print(`{"version":1,"token":"external-token"}`)
	case "literal $(false)":
		fmt.Print(`{"version":1,"token":"literal-argument"}`)
	case "bad":
		fmt.Print(`secret malformed response`)
	case "version":
		fmt.Print(`{"version":2,"token":"secret"}`)
	case "empty":
		fmt.Print(`{"version":1,"token":""}`)
	case "expired":
		fmt.Print(`{"version":1,"token":"secret","expires_at":"2000-01-01T00:00:00Z"}`)
	case "trailing":
		fmt.Print(`{"version":1,"token":"secret"} {}`)
	case "large":
		fmt.Print(strings.Repeat("secret", maxTokenOutput))
	case "fail":
		fmt.Fprint(os.Stderr, "secret stderr")
		fmt.Print("secret stdout")
		os.Exit(7)
	case "wait":
		time.Sleep(time.Minute)
	case "login":
		fmt.Print("explicit login")
	default:
		os.Exit(9)
	}
	os.Exit(0)
}

func TestProcessProvider(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"ok", "literal $(false)", "bad", "version", "empty", "expired", "trailing", "large", "fail", "wait"} {
		t.Run(mode, func(t *testing.T) {
			settings := SourceConfig{"command": []string{executable, "-test.run=^TestProcessHelper$", "--", mode}}
			provider, err := processProviderFactory(settings)
			if err != nil {
				t.Fatal(err)
			}
			ctx := t.Context()
			if mode == "wait" {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, 100*time.Millisecond)
				defer cancel()
			}
			token, err := provider.RetrieveWebIdentityToken(ctx)
			switch mode {
			case "ok":
				if err != nil || token != "external-token" {
					t.Fatalf("%q, %v", token, err)
				}
			case "literal $(false)":
				if err != nil || token != "literal-argument" {
					t.Fatalf("%q, %v", token, err)
				}
			default:
				if err == nil || token != "" || strings.Contains(err.Error(), "secret") {
					t.Fatalf("helper failure leaked output or succeeded: %q, %v", token, err)
				}
				if mode == "wait" && !errors.Is(err, context.DeadlineExceeded) {
					t.Fatalf("lost cancellation: %v", err)
				}
			}
		})
	}
}

func TestProcessLoginAndPATHResolution(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	if err := os.Symlink(executable, filepath.Join(directory, "identity-helper")); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", directory)
	provider, err := processProviderFactory(SourceConfig{
		"command":       []string{"identity-helper", "-test.run=^TestProcessHelper$", "--", "ok"},
		"login_command": []string{"identity-helper", "-test.run=^TestProcessHelper$", "--", "login"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if token, err := provider.RetrieveWebIdentityToken(t.Context()); err != nil || token != "external-token" {
		t.Fatalf("PATH source: %q, %v", token, err)
	}
	var output strings.Builder
	if err := provider.(InteractiveSource).Login(t.Context(), &output); err != nil || output.String() != "explicit login" {
		t.Fatalf("explicit login: %q, %v", output.String(), err)
	}
	for _, path := range []string{"./identity-helper", "../identity-helper", ".", ""} {
		if _, err := processProviderFactory(SourceConfig{"command": []string{path}}); err == nil {
			t.Fatalf("accepted relative executable %q", path)
		}
	}
}

func TestConfigFileLocation(t *testing.T) {
	env := map[string]string{}
	lookup := func(key string) string { return env[key] }
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	path, err := ConfigFilePath(lookup)
	if err != nil || path != filepath.Join(home, ".config", "iq", "config.toml") {
		t.Fatalf("home path: %q, %v", path, err)
	}
	env["XDG_CONFIG_HOME"] = "/xdg"
	path, err = ConfigFilePath(lookup)
	if err != nil || path != "/xdg/iq/config.toml" {
		t.Fatalf("XDG path: %q, %v", path, err)
	}
	env[ConfigFileEnv] = "/custom/profile.toml"
	path, err = ConfigFilePath(lookup)
	if err != nil || path != env[ConfigFileEnv] {
		t.Fatalf("explicit path: %q, %v", path, err)
	}
}

func TestWorkloadDiscoveryWithoutTOML(t *testing.T) {
	for _, prefix := range []string{"IQ_", "MOTIVEIQ_"} {
		t.Run(prefix, func(t *testing.T) {
			r, env := testResolver(t)
			path := filepath.Join(t.TempDir(), "projected-token")
			env[prefix+"ROLE_URN"] = testRole
			env[prefix+"WEB_IDENTITY_TOKEN_FILE"] = path
			env[prefix+"STS_ENDPOINT"] = "sts.workload.example:443"
			identity, err := r.Resolve("")
			if err != nil {
				t.Fatal(err)
			}
			if identity.ProfileName != "" || identity.RoleURN != testRole || identity.STSEndpoint != "sts.workload.example:443" {
				t.Fatalf("workload not selected: %+v", identity)
			}
			// Kubernetes replaces projected files during rotation. Each retrieval
			// must open the current file instead of holding its original inode.
			for _, token := range []string{"initial", "rotated"} {
				replacement := path + ".new"
				if err := os.WriteFile(replacement, []byte(token), 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.Rename(replacement, path); err != nil {
					t.Fatal(err)
				}
				got, err := identity.Provider.RetrieveWebIdentityToken(t.Context())
				if err != nil || got != token {
					t.Fatalf("rotation: %q, %v", got, err)
				}
			}
			cfg, err := r.Load(t.Context(), "")
			if err != nil {
				t.Fatal(err)
			}
			defer cfg.Close()
			if cfg.RoleURN != testRole || cfg.STSEndpoint != "sts.workload.example:443" {
				t.Fatalf("loaded wrong workload: %+v", cfg)
			}
			if _, err := cfg.Credentials(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestCanonicalWorkloadCannotBorrowLegacyIdentity(t *testing.T) {
	for _, key := range []string{RoleURNEnv, WebIdentityTokenFileEnv} {
		t.Run(key, func(t *testing.T) {
			r, env := testResolver(t)
			writeConfig(t, env, fileConfig("/profile-token"))
			env["MOTIVEIQ_ROLE_URN"] = testRole
			env["MOTIVEIQ_WEB_IDENTITY_TOKEN_FILE"] = "/legacy-token"
			if key == RoleURNEnv {
				env[key] = "urn:motiveiq:iam:role/canonical"
			} else {
				env[key] = "/canonical-token"
			}
			if _, err := r.Resolve(""); err == nil {
				t.Fatal("partial canonical identity fell back")
			}
			env[RoleURNEnv] = "urn:motiveiq:iam:role/canonical"
			env[WebIdentityTokenFileEnv] = "/canonical-token"
			identity, err := r.Resolve("")
			if err != nil || identity.RoleURN != env[RoleURNEnv] {
				t.Fatalf("canonical selection: %+v, %v", identity, err)
			}
			env[ProfileEnv] = "missing"
			if _, err := r.Resolve(""); err == nil {
				t.Fatal("missing explicit profile fell back to workload")
			}
		})
	}
}
