package oidc

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"

	sdkconfig "go.motiveiq.dev/platform/iam/sdk/config"
)

// Run implements explicit login and noninteractive external-token retrieval.
// It never selects a role, creates an IAM session, or handles proof keys.
func Run(ctx context.Context, args []string, output io.Writer) error {
	env := os.Getenv
	if len(args) >= 2 && args[0] == "--config-file" {
		path := args[1]
		env = func(key string) string {
			if key == sdkconfig.ConfigFileEnv {
				return path
			}
			return os.Getenv(key)
		}
		args = args[2:]
	}
	const usage = "Usage: iq-oidc [--config-file FILE] <token|access-token|login> SOURCE"
	if len(args) == 1 && (args[0] == "--help" || args[0] == "-h") {
		fmt.Fprintln(output, usage)
		return nil
	}
	if len(args) != 2 || (args[0] != "token" && args[0] != "access-token" && args[0] != "login") {
		return fmt.Errorf("%s", usage)
	}
	config, err := sdkconfig.ReadFile(env)
	if err != nil {
		return err
	}
	source, ok := config.WebIdentitySources[args[1]]
	if !ok || source.Type != "oidc" {
		return fmt.Errorf("source %q is not configured as OIDC", args[1])
	}
	provider, err := newOIDCSource(source.Config)
	if err != nil {
		return err
	}
	if args[0] == "login" {
		if err := provider.Login(ctx, output); err != nil {
			return err
		}
		if provider.config.AccessTokenExportFile == "" {
			return nil
		}
		configPath, err := sdkconfig.ConfigFilePath(env)
		if err != nil {
			return err
		}
		executable, err := os.Executable()
		if err != nil {
			return err
		}
		return exportProcess(provider.config.AccessTokenExportFile, []string{executable, "--config-file", configPath, "access-token", args[1]})
	}
	token, err := provider.token(ctx, args[0] == "access-token")
	if err != nil {
		return err
	}
	return json.NewEncoder(output).Encode(token)
}

// Relative export paths use XDG_CONFIG_HOME, never the working directory.
// Only a process locator is exported; no refresh credential is duplicated.
func exportProcess(path string, command []string) error {
	if !filepath.IsAbs(path) {
		base := os.Getenv("XDG_CONFIG_HOME")
		if base == "" {
			home, err := os.UserHomeDir()
			if err != nil {
				return err
			}
			base = filepath.Join(home, ".config")
		}
		if !filepath.IsLocal(path) || !filepath.IsAbs(base) {
			return fmt.Errorf("invalid access_token_export_file")
		}
		path = filepath.Join(base, path)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return writeJSON(path, map[string]any{"credential_process": command})
}
