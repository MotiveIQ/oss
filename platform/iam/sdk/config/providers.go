package config

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	motiveiq "go.motiveiq.dev/platform/iam/sdk"
)

// NewFileProvider rereads a raw external token on each STS exchange, so token
// rotation is observed. Paths must be absolute and never depend on a workspace.
func NewFileProvider(path string) (motiveiq.WebIdentityTokenProvider, error) {
	if !filepath.IsAbs(path) {
		return nil, fmt.Errorf("web identity token file must be an absolute path")
	}
	return motiveiq.WebIdentityTokenProviderFunc(func(ctx context.Context) (string, error) {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		file, err := os.Open(path)
		if err != nil {
			return "", fmt.Errorf("open web identity token file: %w", err)
		}
		defer file.Close()
		data, err := io.ReadAll(io.LimitReader(file, maxTokenOutput+1))
		if err != nil {
			return "", fmt.Errorf("read web identity token file: %w", err)
		}
		if len(data) > maxTokenOutput {
			return "", fmt.Errorf("web identity token file is too large")
		}
		return nonemptyToken(string(data))
	}), nil
}

func fileProviderFactory(settings SourceConfig) (motiveiq.WebIdentityTokenProvider, error) {
	var config struct {
		Path string `toml:"path"`
	}
	if err := settings.Decode(&config); err != nil {
		return nil, err
	}
	return NewFileProvider(config.Path)
}

// ProcessToken is the versioned external-token helper protocol. It contains no
// IAM session or signing key. Expiration is optional; when supplied it must be in
// the future. Helpers own external-token caching and refresh.
type ProcessToken struct {
	Version   int        `json:"version"`
	Token     string     `json:"token"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

const maxTokenOutput = 1024 * 1024

// InteractiveSource is an optional, explicit login capability. SDK token
// retrieval never invokes it; applications such as iq login may do so.
type InteractiveSource interface {
	Login(context.Context, io.Writer) error
}

type processProvider struct {
	command      []string
	loginCommand []string
}

func validCommand(command []string) bool {
	if len(command) == 0 || command[0] == "" || command[0] == "." || command[0] == ".." {
		return false
	}
	return filepath.IsAbs(command[0]) || !strings.ContainsAny(command[0], "/\\")
}

func processProviderFactory(settings SourceConfig) (motiveiq.WebIdentityTokenProvider, error) {
	var config struct {
		Command      []string `toml:"command"`
		LoginCommand []string `toml:"login_command,omitempty"`
	}
	if err := settings.Decode(&config); err != nil {
		return nil, err
	}
	return NewProcessProvider(config.Command, config.LoginCommand)
}

// NewProcessProvider uses the external-token protocol without profile loading.
// Callers decide the token's purpose; retrieval never invokes loginCommand.
func NewProcessProvider(command, loginCommand []string) (motiveiq.WebIdentityTokenProvider, error) {
	if !validCommand(command) || (len(loginCommand) != 0 && !validCommand(loginCommand)) {
		return nil, fmt.Errorf("web identity process requires an absolute executable or a command name on PATH")
	}
	return &processProvider{command: append([]string(nil), command...), loginCommand: append([]string(nil), loginCommand...)}, nil
}

func (p *processProvider) RetrieveWebIdentityToken(ctx context.Context) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, p.command[0], p.command[1:]...)
	// No shell, terminal input, or inherited stdout/stderr. Never include a
	// helper's output in errors, including when the helper exits unsuccessfully.
	output := &boundedOutput{}
	command.Stdout = output
	command.Stderr = io.Discard
	command.WaitDelay = time.Second
	if err := command.Run(); err != nil {
		if ctx.Err() != nil {
			return "", fmt.Errorf("web identity process: %w", ctx.Err())
		}
		return "", fmt.Errorf("web identity process failed: %w", err)
	}
	if output.overflow {
		return "", fmt.Errorf("web identity process output is too large")
	}
	var result ProcessToken
	decoder := json.NewDecoder(bytes.NewReader(output.data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&result); err != nil {
		return "", fmt.Errorf("invalid web identity process response")
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return "", fmt.Errorf("invalid web identity process response")
	}
	if result.Version != 1 {
		return "", fmt.Errorf("unsupported web identity process response version")
	}
	if result.ExpiresAt != nil && !result.ExpiresAt.After(time.Now()) {
		return "", fmt.Errorf("web identity process returned an expired token")
	}
	return nonemptyToken(result.Token)
}

func (p *processProvider) Login(ctx context.Context, output io.Writer) error {
	if len(p.loginCommand) == 0 {
		return fmt.Errorf("web identity source has no login_command; authenticate with its provider")
	}
	command := exec.CommandContext(ctx, p.loginCommand[0], p.loginCommand[1:]...)
	command.Stdin, command.Stdout, command.Stderr = os.Stdin, output, output
	command.WaitDelay = time.Second
	if err := command.Run(); err != nil {
		return fmt.Errorf("web identity login process failed: %w", err)
	}
	return nil
}

type boundedOutput struct {
	data     []byte
	overflow bool
}

func (b *boundedOutput) Write(p []byte) (int, error) {
	n := len(p)
	remaining := maxTokenOutput - len(b.data)
	if n > remaining {
		p = p[:remaining]
		b.overflow = true
	}
	b.data = append(b.data, p...)
	return n, nil
}

func nonemptyToken(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", fmt.Errorf("web identity source returned an empty token")
	}
	return value, nil
}
