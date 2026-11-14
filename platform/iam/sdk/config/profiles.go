package config

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/pelletier/go-toml/v2"

	motiveiq "go.motiveiq.dev/platform/iam/sdk"
	"go.motiveiq.dev/platform/iam/sdk/internal/envconfig"
)

const (
	ConfigFileEnv           = "IQ_CONFIG_FILE"
	ProfileEnv              = "IQ_PROFILE"
	RoleURNEnv              = motiveiq.EnvRoleURN
	WebIdentityTokenFileEnv = motiveiq.EnvWebIdentityTokenFile
	STSEndpointEnv          = motiveiq.EnvSTSEndpoint
	STSProofOriginEnv       = motiveiq.EnvSTSProofOrigin
	SessionNameEnv          = motiveiq.EnvSessionName
)

type Profile struct {
	RoleURN           string `toml:"role_urn"`
	WebIdentitySource string `toml:"web_identity_source"`
	STSEndpoint       string `toml:"sts_endpoint,omitempty"`
}

// Source's configuration is interpreted only by its registered factory.
type Source struct {
	Type   string       `toml:"type"`
	Config SourceConfig `toml:"config"`
}

type FileConfig struct {
	Profiles           map[string]Profile `toml:"profiles"`
	WebIdentitySources map[string]Source  `toml:"web_identity_sources"`
}

// SourceConfig holds the provider-specific TOML table. Each factory decodes its
// own schema; the resolver does not need to know the provider's settings.
type SourceConfig map[string]any

func (c SourceConfig) Decode(destination any) error {
	data, err := toml.Marshal(c)
	if err != nil {
		return fmt.Errorf("invalid web identity source configuration")
	}
	return DecodeConfig(data, destination)
}

type ProviderFactory func(SourceConfig) (motiveiq.WebIdentityTokenProvider, error)

type Identity struct {
	ProfileName    string
	RoleURN        string
	STSEndpoint    string
	STSProofOrigin string
	SessionName    string
	Provider       motiveiq.WebIdentityTokenProvider
}

// Resolver chooses one source. A configured source's errors are terminal;
// discovery never retrieves a token, launches a helper, or falls back on failure.
type Resolver struct {
	Profile           string
	Env               func(string) string
	ProviderFactories map[string]ProviderFactory
}

func (r Resolver) Resolve(roleOverride string) (Identity, error) {
	env := r.Env
	if env == nil {
		env = os.Getenv
	}
	name := strings.TrimSpace(r.Profile)
	if name == "" {
		name = strings.TrimSpace(env(ProfileEnv))
	}
	if name == "" && (envconfig.Get(env, WebIdentityTokenFileEnv) != "" || envconfig.Get(env, RoleURNEnv) != "") {
		role := strings.TrimSpace(envconfig.Get(env, RoleURNEnv))
		if roleOverride != "" {
			role = roleOverride
		}
		if role == "" || envconfig.Get(env, WebIdentityTokenFileEnv) == "" {
			return Identity{}, fmt.Errorf("environment identity requires %s and a role (%s or --role)", WebIdentityTokenFileEnv, RoleURNEnv)
		}
		provider, err := NewFileProvider(envconfig.Get(env, WebIdentityTokenFileEnv))
		return Identity{RoleURN: role, STSEndpoint: envconfig.Get(env, STSEndpointEnv), STSProofOrigin: envconfig.Get(env, STSProofOriginEnv), SessionName: envconfig.Get(env, SessionNameEnv), Provider: provider}, err
	}
	explicitProfile := name != ""
	if name == "" {
		name = "default"
	}
	config, err := ReadFile(env)
	if err != nil {
		return Identity{}, err
	}
	profile, ok := config.Profiles[name]
	if !ok {
		return Identity{}, fmt.Errorf("profile %q is not configured; configure %s or environment web identity", name, ConfigFileEnv)
	}
	if roleOverride != "" {
		profile.RoleURN = roleOverride
	}
	if strings.TrimSpace(profile.RoleURN) == "" || profile.WebIdentitySource == "" {
		return Identity{}, fmt.Errorf("profile %q requires role_urn and web_identity_source", name)
	}
	source, ok := config.WebIdentitySources[profile.WebIdentitySource]
	if !ok {
		return Identity{}, fmt.Errorf("profile %q references unknown web identity source %q", name, profile.WebIdentitySource)
	}
	var factory ProviderFactory
	switch source.Type {
	case "file":
		factory = fileProviderFactory
	case "process":
		factory = processProviderFactory
	default:
		factory = r.ProviderFactories[source.Type]
	}
	if factory == nil {
		return Identity{}, fmt.Errorf("unsupported web identity source type %q", source.Type)
	}
	provider, err := factory(source.Config)
	if err != nil {
		return Identity{}, fmt.Errorf("web identity source %q: %w", profile.WebIdentitySource, err)
	}
	if provider == nil {
		return Identity{}, fmt.Errorf("web identity source %q returned no provider", profile.WebIdentitySource)
	}
	if !explicitProfile && envconfig.Get(env, STSEndpointEnv) != "" {
		profile.STSEndpoint = envconfig.Get(env, STSEndpointEnv)
	}
	return Identity{ProfileName: name, RoleURN: profile.RoleURN, STSEndpoint: profile.STSEndpoint, STSProofOrigin: envconfig.Get(env, STSProofOriginEnv), SessionName: envconfig.Get(env, SessionNameEnv), Provider: provider}, nil
}

// ConfigFilePath is shared by clients and the internal package installer.
// An explicit IQ_CONFIG_FILE takes precedence over the XDG location.
func ConfigFilePath(env func(string) string) (string, error) {
	if env == nil {
		env = os.Getenv
	}
	if path := env(ConfigFileEnv); path != "" {
		return path, nil
	}
	base := env("XDG_CONFIG_HOME")
	if base == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		base = filepath.Join(home, ".config")
	}
	return filepath.Join(base, "iq", "config.toml"), nil
}

// ReadFile reads shared configuration without selecting a role or invoking a
// provider. External-token helpers can read their own source settings with it.
func ReadFile(env func(string) string) (FileConfig, error) {
	if env == nil {
		env = os.Getenv
	}
	path, err := ConfigFilePath(env)
	if err != nil {
		return FileConfig{}, err
	}
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) && env(ConfigFileEnv) == "" {
		return FileConfig{}, nil
	}
	if err != nil {
		return FileConfig{}, fmt.Errorf("read identity configuration: %w", err)
	}
	var config FileConfig
	if err := DecodeConfig(data, &config); err != nil {
		return FileConfig{}, err
	}
	return config, nil
}

// DecodeConfig strictly decodes TOML configuration without including input
// fragments in errors; provider settings may contain secrets.
func DecodeConfig(data []byte, destination any) error {
	decoder := toml.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return fmt.Errorf("invalid identity configuration TOML")
	}
	return nil
}
