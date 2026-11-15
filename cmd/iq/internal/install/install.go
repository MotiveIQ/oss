package install

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
)

func (c *Command) CobraCommand() *cobra.Command {
	c.applyDefaults()
	return &cobra.Command{
		Use:               "install PACKAGE",
		Short:             "Build and install a declared MotiveIQ package.",
		Args:              cobra.ExactArgs(1),
		ValidArgsFunction: c.completePackages,
		RunE: func(cmd *cobra.Command, args []string) error {
			return c.runInstall(cmd.Context(), args[0])
		},
	}
}

func (c *Command) runInstall(ctx context.Context, name string) error {
	pkg, err := c.packageByName(ctx, name)
	if err != nil {
		return err
	}
	root, err := FindWorkspaceRoot()
	if err != nil {
		return err
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("find home directory: %w", err)
	}
	prefix := filepath.Join(home, ".local")
	if err := c.RunInteractiveCommandInDir(ctx, root, "bazel", "run", "-c", "opt", pkg.Installer, "--", "--destdir", prefix); err != nil {
		return fmt.Errorf("install %q with %s: %w", pkg.Name, pkg.Installer, err)
	}

	binDir := filepath.Join(prefix, "bin")
	destination := filepath.Join(binDir, pkg.InstallName)
	fmt.Fprintf(c.Stdout, "installed %s to %s\n", pkg.Name, destination)
	if !pathContainsDirectory(c.Env("PATH"), binDir) {
		fmt.Fprintf(c.Stderr, "note: add %s to PATH to run installed packages\n", binDir)
	}
	return nil
}

func (c *Command) completePackages(cmd *cobra.Command, args []string, toComplete string) ([]cobra.Completion, cobra.ShellCompDirective) {
	if len(args) > 0 {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	packages, err := c.ListPackages(cmd.Context())
	if err != nil {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	completions := make([]cobra.Completion, 0, len(packages))
	for _, pkg := range packages {
		if !strings.HasPrefix(pkg.Name, toComplete) {
			continue
		}
		description := pkg.Description
		if description == "" {
			description = "package"
		}
		completions = append(completions, cobra.CompletionWithDesc(pkg.Name, description))
	}
	return completions, cobra.ShellCompDirectiveNoFileComp
}

func pathContainsDirectory(pathValue, directory string) bool {
	directory = filepath.Clean(directory)
	for _, candidate := range filepath.SplitList(pathValue) {
		if filepath.Clean(candidate) == directory {
			return true
		}
	}
	return false
}
