package publiccli

import (
	"context"
	"io"
	"slices"
	"strings"
	"testing"

	"go.motiveiq.dev/platform/iam/oauth"
	motiveiq "go.motiveiq.dev/platform/iam/sdk"
)

func TestAPICommandsOutsideWorkspace(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv("BUILD_WORKSPACE_DIRECTORY", "")
	t.Setenv("BUILD_WORKING_DIRECTORY", "")
	command := NewCommand()
	command.Stdout = &strings.Builder{}
	command.Stderr = &strings.Builder{}
	command.Env = func(string) string { return "" }
	command.LoadSDKConfig = func(context.Context, string) (*motiveiq.Config, error) {
		t.Fatal("help attempted to load credentials or connect to a service")
		return nil, nil
	}
	var names []string
	for _, subcommand := range command.Commands() {
		names = append(names, subcommand.Name())
	}
	slices.Sort(names)
	want := []string{"iam", "kms", "login", "s3", "secretsmanager", "sts", "whoami"}
	if !slices.Equal(names, want) {
		t.Fatalf("API commands = %v, want %v", names, want)
	}
	for _, name := range names {
		if code := command.Run(context.Background(), []string{name, "--help"}); code != 0 {
			t.Fatalf("%s --help exited %d: %s", name, code, command.Stderr)
		}
	}
	for _, name := range []string{"build", "run", "deploy", "setup", "install", "terraform", "blob"} {
		if code := command.Run(context.Background(), []string{name}); code == 0 {
			t.Fatalf("internal command %s is available in the API CLI", name)
		}
	}
}

func TestLoginHasNoWorkspaceGuidance(t *testing.T) {
	command := NewCommand()
	stdout := &strings.Builder{}
	command.Stdout = stdout
	command.Login = func(context.Context, io.Writer) (oauth.Credentials, error) {
		return oauth.Credentials{"refresh_token": "test-refresh-token"}, nil
	}
	var saved oauth.Credentials
	command.SaveCredentials = func(credentials oauth.Credentials) (string, error) {
		saved = credentials
		return "/test/credentials.json", nil
	}
	if code := command.Run(context.Background(), []string{"login"}); code != 0 {
		t.Fatalf("login exited %d", code)
	}
	if saved["refresh_token"] != "test-refresh-token" || !strings.Contains(stdout.String(), "saved credentials") {
		t.Fatalf("login did not save credentials: %s", stdout)
	}
	if strings.Contains(stdout.String(), "buildfarm") || strings.Contains(stdout.String(), "iq build") {
		t.Fatalf("standalone login contains internal guidance: %s", stdout)
	}
}
