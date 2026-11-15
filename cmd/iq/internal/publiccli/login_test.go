package publiccli

import (
	"context"
	"io"
	"strings"
	"testing"

	motiveiq "go.motiveiq.dev/platform/iam/sdk"
	sdkconfig "go.motiveiq.dev/platform/iam/sdk/config"
)

type interactiveIdentity struct {
	motiveiq.WebIdentityTokenProvider
	login func(context.Context, io.Writer) error
}

func (p interactiveIdentity) Login(ctx context.Context, output io.Writer) error {
	return p.login(ctx, output)
}

func TestLoginUsesSelectedProfileOutsideWorkspace(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv("BUILD_WORKSPACE_DIRECTORY", "")
	c := NewCommand()
	c.Stdout, c.Stderr = &strings.Builder{}, &strings.Builder{}
	called := false
	provider := motiveiq.WebIdentityTokenProviderFunc(func(context.Context) (string, error) {
		t.Fatal("login retrieved a token or assumed a role")
		return "", nil
	})
	c.ResolveIdentity = func(role string) (sdkconfig.Identity, error) {
		if c.Profile != "external" || role != "" {
			t.Fatalf("profile=%q role=%q", c.Profile, role)
		}
		return sdkconfig.Identity{Provider: interactiveIdentity{provider, func(_ context.Context, output io.Writer) error {
			called = true
			_, err := io.WriteString(output, "provider login")
			return err
		}}}, nil
	}
	if code := c.Run(t.Context(), []string{"login", "--profile", "external"}); code != 0 || !called || c.Stdout.(*strings.Builder).String() != "provider login" {
		t.Fatalf("login: code=%d called=%v stdout=%s stderr=%s", code, called, c.Stdout, c.Stderr)
	}
	c.ResolveIdentity = func(string) (sdkconfig.Identity, error) {
		return sdkconfig.Identity{Provider: provider}, nil
	}
	if code := c.Run(t.Context(), []string{"login"}); code != 1 || !strings.Contains(c.Stderr.(*strings.Builder).String(), "does not support interactive login") {
		t.Fatalf("noninteractive login: code=%d stderr=%s", code, c.Stderr)
	}
}
