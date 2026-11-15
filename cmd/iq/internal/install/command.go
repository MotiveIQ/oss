// Package install installs declared Bazel packages. It has no identity or
// company configuration; the selected package owns its payload and defaults.
package install

import (
	"bytes"
	"context"
	"io"
	"os"
	"os/exec"
)

type CommandResult struct {
	Stdout string
	Stderr string
}

type Command struct {
	Stdin                      io.Reader
	Stdout, Stderr             io.Writer
	Env                        func(string) string
	RunCommandInDir            func(context.Context, string, string, ...string) (CommandResult, error)
	RunInteractiveCommandInDir func(context.Context, string, string, ...string) error
	ListPackages               func(context.Context) ([]Package, error)
}

func NewCommand() *Command {
	c := &Command{Stdin: os.Stdin, Stdout: os.Stdout, Stderr: os.Stderr}
	c.applyDefaults()
	return c
}

func (c *Command) applyDefaults() {
	if c.Stdin == nil {
		c.Stdin = os.Stdin
	}
	if c.Stdout == nil {
		c.Stdout = io.Discard
	}
	if c.Stderr == nil {
		c.Stderr = io.Discard
	}
	if c.Env == nil {
		c.Env = os.Getenv
	}
	if c.ListPackages == nil {
		c.ListPackages = c.listPackages
	}
	if c.RunCommandInDir == nil {
		c.RunCommandInDir = func(ctx context.Context, dir, name string, args ...string) (CommandResult, error) {
			command := exec.CommandContext(ctx, name, args...)
			command.Dir = dir
			var stdout, stderr bytes.Buffer
			command.Stdout, command.Stderr = &stdout, &stderr
			err := command.Run()
			return CommandResult{Stdout: stdout.String(), Stderr: stderr.String()}, err
		}
	}
	if c.RunInteractiveCommandInDir == nil {
		c.RunInteractiveCommandInDir = func(ctx context.Context, dir, name string, args ...string) error {
			command := exec.CommandContext(ctx, name, args...)
			command.Dir = dir
			command.Stdin, command.Stdout, command.Stderr = c.Stdin, c.Stdout, c.Stderr
			return command.Run()
		}
	}
}
