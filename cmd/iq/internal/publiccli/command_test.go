package publiccli

import (
	"context"
	"slices"
	"strings"
	"testing"

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
	want := []string{"iam", "kms", "s3", "secretsmanager", "sts"}
	if !slices.Equal(names, want) {
		t.Fatalf("API commands = %v, want %v", names, want)
	}
	for _, name := range names {
		if code := command.Run(context.Background(), []string{name, "--help"}); code != 0 {
			t.Fatalf("%s --help exited %d: %s", name, code, command.Stderr)
		}
	}
	for _, name := range []string{"login", "whoami", "build", "run", "deploy", "setup", "install", "terraform", "blob"} {
		if code := command.Run(context.Background(), []string{name}); code == 0 {
			t.Fatalf("internal command %s is available in the API CLI", name)
		}
	}
}

func TestProfileFlagResolvesBeforeServiceCall(t *testing.T) {
	for _, args := range [][]string{{"--profile", "production", "sts", "get-caller-identity"}, {"sts", "get-caller-identity", "--profile", "production"}} {
		fixture := newIAMTestFixture(t)
		fixture.command.LoadSDKConfig = func(ctx context.Context, role string) (*motiveiq.Config, error) {
			if fixture.command.Profile != "production" || role != "" {
				t.Fatalf("profile=%q role=%q", fixture.command.Profile, role)
			}
			return testSDKConfig(ctx, "urn:motiveiq:iam:role/production")
		}
		if code := fixture.command.Run(context.Background(), args); code != 0 {
			t.Fatalf("profile command failed: %s", fixture.stderr())
		}
	}
}
