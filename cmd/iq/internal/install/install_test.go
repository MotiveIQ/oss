package install

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func runCommand(command *Command, args []string) int {
	root := &cobra.Command{Use: "iq", SilenceUsage: true, SilenceErrors: true}
	root.AddCommand(command.CobraCommand())
	root.SetArgs(args)
	root.SetOut(command.Stdout)
	root.SetErr(command.Stderr)
	if err := root.ExecuteContext(context.Background()); err != nil {
		return 1
	}
	return 0
}

func TestListPackagesQueriesBazelGraph(t *testing.T) {
	workspace := t.TempDir()
	if err := os.WriteFile(filepath.Join(workspace, "MODULE.bazel"), []byte("module(name = \"test\")\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("BUILD_WORKSPACE_DIRECTORY", workspace)
	command := NewCommand()
	var gotDir string
	var gotName string
	var gotArgs []string
	command.RunCommandInDir = func(_ context.Context, dir string, name string, args ...string) (CommandResult, error) {
		gotDir = dir
		gotName = name
		gotArgs = append([]string(nil), args...)
		return CommandResult{Stdout: packageQueryXMLFixture}, nil
	}

	packages, err := command.listPackages(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(packages) != 2 || packages[0].Name != "example" || packages[1].Name != "iq" {
		t.Fatalf("unexpected packages: %#v", packages)
	}
	if gotDir != workspace || gotName != "bazel" {
		t.Fatalf("unexpected command: dir=%q name=%q args=%#v", gotDir, gotName, gotArgs)
	}
	if strings.Join(gotArgs, " ") != `query --output=xml kind("_iq_pkg_descriptor rule", attr("tags", "iq_pkg", //...))` {
		t.Fatalf("unexpected bazel args: %#v", gotArgs)
	}
}

func TestInstallRunsDeclaredRulesPkgInstaller(t *testing.T) {
	workspace := t.TempDir()
	if err := os.WriteFile(filepath.Join(workspace, "MODULE.bazel"), []byte("module(name = \"test\")\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	home := t.TempDir()
	prefix := filepath.Join(home, ".local")
	binDir := filepath.Join(prefix, "bin")
	t.Setenv("BUILD_WORKSPACE_DIRECTORY", workspace)
	t.Setenv("HOME", home)

	command := NewCommand()
	command.Stdout = &strings.Builder{}
	command.Stderr = &strings.Builder{}
	command.Env = func(name string) string {
		if name == "PATH" {
			return binDir
		}
		return ""
	}
	command.ListPackages = func(context.Context) ([]Package, error) {
		return []Package{{
			Name:        "iq",
			InstallName: "iq",
			Installer:   "//cmd/iq:package_installer",
		}}, nil
	}
	var gotDir string
	var gotName string
	var gotArgs []string
	command.RunInteractiveCommandInDir = func(_ context.Context, dir, name string, args ...string) error {
		gotDir = dir
		gotName = name
		gotArgs = append([]string(nil), args...)
		return nil
	}

	code := runCommand(command, []string{"install", "iq"})
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d: %s", code, command.Stderr)
	}
	if gotDir != workspace || gotName != "bazel" {
		t.Fatalf("unexpected command: dir=%q name=%q args=%#v", gotDir, gotName, gotArgs)
	}
	wantArgs := []string{"run", "-c", "opt", "//cmd/iq:package_installer", "--", "--destdir", prefix}
	if strings.Join(gotArgs, "\x00") != strings.Join(wantArgs, "\x00") {
		t.Fatalf("unexpected bazel args: got %#v, want %#v", gotArgs, wantArgs)
	}
	if !strings.Contains(command.Stdout.(*strings.Builder).String(), filepath.Join(binDir, "iq")) {
		t.Fatalf("unexpected stdout: %s", command.Stdout)
	}
	if command.Stderr.(*strings.Builder).Len() != 0 {
		t.Fatalf("unexpected stderr: %s", command.Stderr)
	}
}

func TestInstallWarnsWhenInstallDirectoryIsNotOnPath(t *testing.T) {
	workspace := t.TempDir()
	if err := os.WriteFile(filepath.Join(workspace, "MODULE.bazel"), []byte("module(name = \"test\")\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	home := t.TempDir()
	t.Setenv("BUILD_WORKSPACE_DIRECTORY", workspace)
	t.Setenv("HOME", home)

	command := NewCommand()
	command.Stdout = &strings.Builder{}
	command.Stderr = &strings.Builder{}
	command.Env = func(string) string { return "/usr/bin:/bin" }
	command.ListPackages = func(context.Context) ([]Package, error) {
		return []Package{{Name: "iq", InstallName: "iq", Installer: "//cmd/iq:package_installer"}}, nil
	}
	command.RunInteractiveCommandInDir = func(context.Context, string, string, ...string) error { return nil }

	code := runCommand(command, []string{"install", "iq"})
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d: %s", code, command.Stderr)
	}
	want := filepath.Join(home, ".local", "bin")
	if !strings.Contains(command.Stderr.(*strings.Builder).String(), "add "+want+" to PATH") {
		t.Fatalf("unexpected stderr: %s", command.Stderr)
	}
}

func TestInstallPackageCompletion(t *testing.T) {
	command := NewCommand()
	command.Stdout = &strings.Builder{}
	command.Stderr = &strings.Builder{}
	command.ListPackages = func(context.Context) ([]Package, error) {
		return []Package{
			{Name: "iq", Description: "MotiveIQ CLI"},
			{Name: "example", Description: "Example package"},
		}, nil
	}

	code := runCommand(command, []string{cobra.ShellCompRequestCmd, "install", "e"})
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d: %s", code, command.Stderr)
	}
	stdout := command.Stdout.(*strings.Builder).String()
	if !strings.Contains(stdout, "example\tExample package") || strings.Contains(stdout, "iq\t") {
		t.Fatalf("unexpected package completions: %s", stdout)
	}
}

func TestParseIQPackagesQueryRejectsDuplicatePackageNames(t *testing.T) {
	payload := strings.Replace(
		packageQueryXMLFixture,
		`<string name="package" value="example"/>`,
		`<string name="package" value="iq"/>`,
		1,
	)
	_, err := parseIQPackagesQuery([]byte(payload))
	if err == nil || !strings.Contains(err.Error(), `iq_pkg "iq" is declared by both`) {
		t.Fatalf("expected duplicate package error, got %v", err)
	}
}

func TestParseIQPackagesQueryRejectsDuplicateInstallNames(t *testing.T) {
	payload := strings.Replace(
		packageQueryXMLFixture,
		`<string name="install_name" value="example"/>`,
		`<string name="install_name" value="iq"/>`,
		1,
	)
	_, err := parseIQPackagesQuery([]byte(payload))
	if err == nil || !strings.Contains(err.Error(), `iq_pkg install_name "iq" is declared by both`) {
		t.Fatalf("expected duplicate install_name error, got %v", err)
	}
}

const packageQueryXMLFixture = `<?xml version="1.1" encoding="UTF-8" standalone="no"?>
<query version="2">
    <rule class="_iq_pkg_descriptor" name="//cmd/example:package">
        <string name="description" value="Example package."/>
        <string name="install_name" value="example"/>
        <label name="installer" value="//cmd/example:package_installer"/>
        <string name="package" value="example"/>
    </rule>
    <rule class="_iq_pkg_descriptor" name="//cmd/iq:package">
        <string name="description" value="MotiveIQ developer command line entrypoint."/>
        <string name="install_name" value="iq"/>
        <label name="installer" value="//cmd/iq:package_installer"/>
        <string name="package" value="iq"/>
    </rule>
</query>`
