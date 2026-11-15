package install

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
)

func FindWorkspaceRoot() (string, error) {
	if workspace := os.Getenv("BUILD_WORKSPACE_DIRECTORY"); workspace != "" {
		if _, err := os.Stat(filepath.Join(workspace, "MODULE.bazel")); err == nil {
			return workspace, nil
		}
	}
	wd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for current := wd; ; current = filepath.Dir(current) {
		if _, err := os.Stat(filepath.Join(current, "MODULE.bazel")); err == nil {
			return current, nil
		}
		parent := filepath.Dir(current)
		if parent == current {
			return "", fmt.Errorf("could not find MODULE.bazel above %s", wd)
		}
	}
}

type QueryXML struct {
	Rules []bazelRuleXML `xml:"rule"`
}

type bazelRuleXML struct {
	Name    string              `xml:"name,attr"`
	Strings []StringAttrXML     `xml:"string"`
	Labels  []bazelLabelAttrXML `xml:"label"`
}

type StringAttrXML struct {
	Name  string `xml:"name,attr"`
	Value string `xml:"value,attr"`
}

type bazelLabelAttrXML struct {
	Name  string `xml:"name,attr"`
	Value string `xml:"value,attr"`
}

func NormalizeXML(payload []byte) []byte {
	// Bazel emits XML 1.1, while Go's encoding/xml decoder only accepts 1.0.
	return bytes.Replace(payload, []byte(`<?xml version="1.1"`), []byte(`<?xml version="1.0"`), 1)
}
