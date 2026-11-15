package install

import (
	"context"
	"encoding/xml"
	"fmt"
	"sort"
	"strings"
)

const packageQueryExpression = `kind("_iq_pkg_descriptor rule", attr("tags", "iq_pkg", //...))`

type Package struct {
	Name        string
	Description string
	InstallName string
	Installer   string
}

func (c *Command) listPackages(ctx context.Context) ([]Package, error) {
	root, err := FindWorkspaceRoot()
	if err != nil {
		return nil, err
	}
	result, err := c.RunCommandInDir(ctx, root, "bazel", "query", "--output=xml", packageQueryExpression)
	if err != nil {
		detail := strings.TrimSpace(result.Stderr)
		if detail != "" {
			return nil, fmt.Errorf("bazel query iq_pkg targets: %w: %s", err, detail)
		}
		return nil, fmt.Errorf("bazel query iq_pkg targets: %w", err)
	}
	return parseIQPackagesQuery([]byte(result.Stdout))
}

func parseIQPackagesQuery(payload []byte) ([]Package, error) {
	var query QueryXML
	payload = NormalizeXML(payload)
	if err := xml.Unmarshal(payload, &query); err != nil {
		return nil, fmt.Errorf("parse bazel package query XML: %w", err)
	}

	packages := make([]Package, 0, len(query.Rules))
	seenPackages := map[string]string{}
	seenInstallNames := map[string]string{}
	for _, rule := range query.Rules {
		pkg := Package{}
		for _, attr := range rule.Strings {
			switch attr.Name {
			case "package":
				pkg.Name = attr.Value
			case "description":
				pkg.Description = attr.Value
			case "install_name":
				pkg.InstallName = attr.Value
			}
		}
		for _, attr := range rule.Labels {
			if attr.Name == "installer" {
				pkg.Installer = attr.Value
			}
		}
		if pkg.Name == "" || pkg.InstallName == "" || pkg.Installer == "" {
			return nil, fmt.Errorf("bazel target %s is tagged iq_pkg but has incomplete package metadata", rule.Name)
		}
		if previous, ok := seenPackages[pkg.Name]; ok {
			return nil, fmt.Errorf("iq_pkg %q is declared by both %s and %s", pkg.Name, previous, rule.Name)
		}
		if previous, ok := seenInstallNames[pkg.InstallName]; ok {
			return nil, fmt.Errorf("iq_pkg install_name %q is declared by both %s and %s", pkg.InstallName, previous, rule.Name)
		}
		seenPackages[pkg.Name] = rule.Name
		seenInstallNames[pkg.InstallName] = rule.Name
		packages = append(packages, pkg)
	}
	sort.Slice(packages, func(i, j int) bool {
		return packages[i].Name < packages[j].Name
	})
	return packages, nil
}

func (c *Command) packageByName(ctx context.Context, name string) (Package, error) {
	packages, err := c.ListPackages(ctx)
	if err != nil {
		return Package{}, fmt.Errorf("load installable packages: %w", err)
	}
	names := make([]string, 0, len(packages))
	for _, pkg := range packages {
		if pkg.Name == name {
			return pkg, nil
		}
		names = append(names, pkg.Name)
	}
	if len(names) == 0 {
		return Package{}, fmt.Errorf("%q is not a declared iq_pkg", name)
	}
	return Package{}, fmt.Errorf("%q is not a declared iq_pkg; expected one of: %s", name, strings.Join(names, ", "))
}
