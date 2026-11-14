package publiccli

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestIAMDefaultJSONAllVerbs(t *testing.T) {
	for _, verb := range iamVerbs() {
		t.Run(verb.use, func(t *testing.T) {
			args := []string{"iam", verb.use}
			if verb.flag != "" {
				args = append(args, "--"+verb.flag, "example")
			}
			out := runIAMOutput(t, args)
			if !json.Valid([]byte(out)) || !strings.HasPrefix(out, "{\n    \"") || !strings.HasSuffix(out, "\n}\n") {
				t.Fatalf("default output is not pretty JSON:\n%s", out)
			}
			if explicit := runIAMOutput(t, append(args, "--output", "json")); explicit != out {
				t.Fatalf("explicit JSON differs from default:\n%s", explicit)
			}
		})
	}
}

func TestIAMDefaultJSONEmptyCollections(t *testing.T) {
	for command, field := range map[string]string{
		"list-resource-policies":   "resourcePolicies",
		"list-service-definitions": "serviceDefinitions",
	} {
		out := runIAMOutput(t, []string{"iam", command})
		want := "{\n    \"" + field + "\": []\n}\n"
		if out != want {
			t.Fatalf("%s: got %q, want %q", command, out, want)
		}
	}
}

func TestIAMOutputEnvironmentAndFlagPlacement(t *testing.T) {
	for _, args := range [][]string{
		{"iam", "list-roles"},
		{"iam", "--output", "text", "list-roles"},
		{"iam", "list-roles", "-o", "text"},
	} {
		fixture := newIAMTestFixture(t)
		fixture.command.Env = func(key string) string {
			if key == defaultOutputEnv {
				return "text"
			}
			return ""
		}
		if code := fixture.command.Run(context.Background(), args); code != 0 {
			t.Fatalf("%v: exit %d: %s", args, code, fixture.stderr())
		}
		if fixture.stdout() != "human\turn:motiveiq:iam:role/human\n" {
			t.Fatalf("%v: unexpected text %q", args, fixture.stdout())
		}
	}
	fixture := newIAMTestFixture(t)
	fixture.command.Env = func(string) string { return "invalid-environment-format" }
	if code := fixture.command.Run(context.Background(), []string{"iam", "--output", "json", "list-roles"}); code != 0 {
		t.Fatalf("explicit format must override env: %s", fixture.stderr())
	}
	if !json.Valid([]byte(fixture.stdout())) {
		t.Fatalf("output: %q", fixture.stdout())
	}
}

func TestIAMQueries(t *testing.T) {
	for _, test := range []struct {
		query, format, want string
	}{
		{"roles[].name", "text", "human\n"},
		{"roles[].[urn,name]", "text", "urn:motiveiq:iam:role/human\thuman\n"},
		{"roles[?name == 'human'].{Name:name,URN:urn}", "json", "[\n    {\n        \"Name\": \"human\",\n        \"URN\": \"urn:motiveiq:iam:role/human\"\n    }\n]\n"},
		{"roles[?name == 'missing']", "json", "[]\n"},
		{"roles[?name == 'missing']", "text", ""},
		{"roles[?name == 'missing']", "table", ""},
		{"roles[0].missing", "text", "None\n"},
		{"roles[0].missing", "json", "null\n"},
		{"length(roles)", "text", "1\n"},
		{"contains(roles[].name, 'human')", "text", "True\n"},
		{"roles[].name", "yaml", "- human\n"},
	} {
		t.Run(test.query+"/"+test.format, func(t *testing.T) {
			out := runIAMOutput(t, []string{"iam", "--query", test.query, "list-roles", "--output", test.format})
			if out != test.want {
				t.Fatalf("got %q, want %q", out, test.want)
			}
		})
	}
}

func TestIAMQueryUsesCompleteResponse(t *testing.T) {
	out := runIAMOutput(t, []string{"iam", "get-oidc-provider", "--name", "hydra", "--query", "issuerCaBundle", "--output", "text"})
	if out != testIssuerCABundle+"\n" {
		t.Fatalf("scalar query must preserve multiline payload: %q", out)
	}
}

func TestIAMQueryTableProjection(t *testing.T) {
	out := runIAMOutput(t, []string{"iam", "list-roles", "--query", "roles[].{URN:urn,Name:name}", "--output", "table"})
	title, headers, rows := parseIAMTable(t, out)
	if title != "iam:ListRoles" || !reflect.DeepEqual(headers, []string{"Name", "URN"}) || !reflect.DeepEqual(rows, [][]string{{"human", "urn:motiveiq:iam:role/human"}}) {
		t.Fatalf("unexpected table:\n%s", out)
	}
}

func TestIAMQueryTableShapes(t *testing.T) {
	for _, test := range []struct {
		query   string
		headers []string
		rows    [][]string
	}{
		{"roles[].[urn,name]", []string{"1", "2"}, [][]string{{"urn:motiveiq:iam:role/human", "human"}}},
		{"roles[].name", []string{"value"}, [][]string{{"human"}}},
		{"roles[0].missing", []string{"value"}, [][]string{{"None"}}},
		{"roles[0].{Name:name,Policies:attachedPolicyUrns}", []string{"field", "value"}, [][]string{{"Name", "human"}, {"Policies", "[]"}}},
	} {
		out := runIAMOutput(t, []string{"iam", "list-roles", "--query", test.query, "-o", "table"})
		_, headers, rows := parseIAMTable(t, out)
		if !reflect.DeepEqual(headers, test.headers) || !reflect.DeepEqual(rows, test.rows) {
			t.Fatalf("%s: unexpected table:\n%s", test.query, out)
		}
	}
}

func TestIdentityCommandsShareOutputOptions(t *testing.T) {
	fixture := newIAMTestFixture(t)
	if code := fixture.command.Run(context.Background(), []string{"sts", "--role", "urn:motiveiq:iam:role/admin", "--query", "roleUrn", "-o", "text", "get-caller-identity"}); code != 0 {
		t.Fatalf("STS: %s", fixture.stderr())
	}
	if !reflect.DeepEqual(fixture.loadedRoles, []string{"urn:motiveiq:iam:role/admin"}) || fixture.stdout() != "urn:motiveiq:iam:role/human\n" {
		t.Fatalf("STS loaded roles %v; output %q", fixture.loadedRoles, fixture.stdout())
	}

}

func TestIAMOutputCompletion(t *testing.T) {
	fixture := newIAMTestFixture(t)
	if code := fixture.command.Run(context.Background(), []string{"__complete", "iam", "list-roles", "--output", ""}); code != 0 {
		t.Fatalf("completion: %s", fixture.stderr())
	}
	for _, format := range []string{"json", "yaml", "text", "table"} {
		if !strings.Contains(fixture.stdout(), format+"\t") {
			t.Fatalf("missing %s completion: %s", format, fixture.stdout())
		}
	}
	if len(fixture.loadedRoles) != 0 {
		t.Fatal("completion loaded credentials")
	}
}

func TestIAMQueryTextNestedRecords(t *testing.T) {
	var out strings.Builder
	writeIAMQueryText(&out, map[string]any{"roles": []any{map[string]any{"urn": "urn:test", "name": "human", "tags": []any{"one", "two"}}}}, "")
	if got, want := out.String(), "ROLES\thuman\turn:test\nTAGS\tone\ttwo\n"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestIAMQueryValidationBeforeCredentials(t *testing.T) {
	for _, args := range [][]string{
		{"iam", "list-roles"}, {"sts", "get-caller-identity"},
	} {
		fixture := newIAMTestFixture(t)

		if code := fixture.command.Run(context.Background(), append(args, "--query", "roles[")); code == 0 {
			t.Fatal("invalid query succeeded")
		}
		if !strings.Contains(fixture.stderr(), "invalid --query") || fixture.stdout() != "" {
			t.Fatalf("stdout %q, stderr %q", fixture.stdout(), fixture.stderr())
		}
		if len(fixture.loadedRoles) != 0 {
			t.Fatal("invalid query loaded credentials")
		}
	}
}

func TestIAMQueryEvaluationFailure(t *testing.T) {
	fixture := newIAMTestFixture(t)
	if code := fixture.command.Run(context.Background(), []string{"iam", "list-roles", "--query", "length(roles[0].missing)"}); code == 0 {
		t.Fatal("invalid query evaluation succeeded")
	}
	if !strings.Contains(fixture.stderr(), "evaluate --query") || fixture.stdout() != "" {
		t.Fatalf("stdout %q, stderr %q", fixture.stdout(), fixture.stderr())
	}
}

func TestIAMYAMLPreservesJSONTypes(t *testing.T) {
	out := runIAMOutput(t, []string{"iam", "get-resource-policy", "--resource-urn", "urn:test", "--output", "yaml"})
	var result map[string]any
	if err := yaml.Unmarshal([]byte(out), &result); err != nil {
		t.Fatal(err)
	}
	if result["resourceUrn"] != "urn:test" || result["revisionNumber"] != "3" {
		t.Fatalf("YAML changed protojson fields or types: %v", result)
	}
	// Keep unqueried numeric JSON exact even above the float64 precision limit.
	var buffer strings.Builder
	command := &Command{Stdout: &buffer}
	if err := command.printOutput(outputOptions{Output: outputYAML}, "test", []byte(`{"number":9007199254740993,"string":"9007199254740993","flag":false}`), nil); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buffer.String(), "number: 9007199254740993\n") || !strings.Contains(buffer.String(), "string: \"9007199254740993\"\n") {
		t.Fatalf("YAML lost precision or string type: %s", buffer.String())
	}
}

type failingIAMWriter struct{}

func (failingIAMWriter) Write([]byte) (int, error) { return 0, errors.New("write failed") }

func TestIAMOutputWriteErrors(t *testing.T) {
	for _, format := range []string{"json", "yaml", "table", "text"} {
		fixture := newIAMTestFixture(t)
		fixture.command.Stdout = failingIAMWriter{}
		if code := fixture.command.Run(context.Background(), []string{"iam", "list-roles", "--output", format}); code == 0 {
			t.Fatalf("%s ignored stdout error", format)
		}
		if !strings.Contains(fixture.stderr(), "write failed") {
			t.Fatalf("%s: %s", format, fixture.stderr())
		}
	}
}
