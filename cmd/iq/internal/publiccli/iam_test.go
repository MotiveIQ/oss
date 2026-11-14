package publiccli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	iamv1 "go.motiveiq.dev/platform/iam/api/v1"
	motiveiq "go.motiveiq.dev/platform/iam/sdk"
)

func TestIAMVerbRPCMapping(t *testing.T) {
	tests := []struct {
		args    []string
		method  string
		request proto.Message
	}{
		{[]string{"iam", "list-roles"}, "ListRoles", &iamv1.ListRolesRequest{}},
		{[]string{"iam", "get-role", "--name", "human"}, "GetRole", &iamv1.GetRoleRequest{Name: "human"}},
		{[]string{"iam", "list-policies"}, "ListPolicies", &iamv1.ListPoliciesRequest{}},
		{[]string{"iam", "get-policy", "--name", "human-cli"}, "GetPolicy", &iamv1.GetPolicyRequest{Name: "human-cli"}},
		{[]string{"iam", "list-oidc-providers"}, "ListOIDCProviders", &iamv1.ListOIDCProvidersRequest{}},
		{[]string{"iam", "get-oidc-provider", "--name", "hydra"}, "GetOIDCProvider", &iamv1.GetOIDCProviderRequest{Name: "hydra"}},
		{[]string{"iam", "list-resource-policies"}, "ListResourcePolicies", &iamv1.ListResourcePoliciesRequest{}},
		{[]string{"iam", "get-resource-policy", "--resource-urn", "urn:motiveiq:temporal:namespace/motiveiq/orders"}, "GetResourcePolicy", &iamv1.GetResourcePolicyRequest{ResourceUrn: "urn:motiveiq:temporal:namespace/motiveiq/orders"}},
		{[]string{"iam", "list-service-definitions"}, "ListServiceDefinitions", &iamv1.ListServiceDefinitionsRequest{}},
		{[]string{"iam", "get-service-definition", "--name", "temporal"}, "GetServiceDefinition", &iamv1.GetServiceDefinitionRequest{Name: "temporal"}},
	}
	for _, test := range tests {
		t.Run(strings.Join(test.args, " "), func(t *testing.T) {
			fixture := newIAMTestFixture(t)
			code := fixture.command.Run(context.Background(), test.args)
			if code != 0 {
				t.Fatalf("exit code %d, stderr: %s", code, fixture.stderr())
			}
			if fixture.iam.method != test.method {
				t.Fatalf("called %q, want %q", fixture.iam.method, test.method)
			}
			if !proto.Equal(fixture.iam.request, test.request) {
				t.Fatalf("request %v, want %v", fixture.iam.request, test.request)
			}
			if len(fixture.loadedRoles) != 1 || fixture.loadedRoles[0] != "" {
				t.Fatalf("loaded roles = %v, want %q", fixture.loadedRoles, "")
			}
			if fixture.iamDials != 1 || fixture.stsDials != 0 {
				t.Fatalf("client construction IAM/STS = %d/%d", fixture.iamDials, fixture.stsDials)
			}
		})
	}
}

func TestIAMEndpointEnvOverride(t *testing.T) {
	command := NewCommand()
	command.Env = func(name string) string {
		if name == IAMEndpointEnv {
			return "localhost:9443"
		}
		return ""
	}
	useTestIdentity(command, func(context.Context) (string, error) { return "web-identity", nil })
	config, err := command.loadSDKConfig(context.Background(), testRoleURN)
	if err != nil {
		t.Fatalf("loadSDKConfig: %v", err)
	}
	defer config.Close()
	if config.STSEndpoint != "localhost:9443" {
		t.Fatalf("STS endpoint = %q", config.STSEndpoint)
	}
	if config.RoleURN != testRoleURN {
		t.Fatalf("role URN = %q", config.RoleURN)
	}
}

func TestIAMRoleOverride(t *testing.T) {
	fixture := newIAMTestFixture(t)
	code := fixture.command.Run(context.Background(), []string{"iam", "list-roles", "--role", "urn:motiveiq:iam:role/admin"})
	if code != 0 {
		t.Fatalf("exit code %d, stderr: %s", code, fixture.stderr())
	}
	if len(fixture.loadedRoles) != 1 || fixture.loadedRoles[0] != "urn:motiveiq:iam:role/admin" {
		t.Fatalf("loaded roles: %v", fixture.loadedRoles)
	}
}

// json is the default, as it is for the AWS CLI: a bare `iq iam list-roles`
// is machine-readable without a flag, and naming the default explicitly
// changes nothing.
func TestIAMDefaultOutputIsJSON(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{"list-roles", []string{"iam", "list-roles"}},
		{"get-role", []string{"iam", "get-role", "--name", "human"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			defaultFixture := newIAMTestFixture(t)
			if code := defaultFixture.command.Run(context.Background(), test.args); code != 0 {
				t.Fatalf("exit code %d, stderr: %s", code, defaultFixture.stderr())
			}
			if !json.Valid([]byte(defaultFixture.stdout())) {
				t.Fatalf("default stdout is not JSON: %q", defaultFixture.stdout())
			}
			jsonFixture := newIAMTestFixture(t)
			if code := jsonFixture.command.Run(context.Background(), append(test.args, "--output", "json")); code != 0 {
				t.Fatalf("--output json exit code %d, stderr: %s", code, jsonFixture.stderr())
			}
			if jsonFixture.stdout() != defaultFixture.stdout() {
				t.Fatalf("--output json stdout %q, want the default's %q", jsonFixture.stdout(), defaultFixture.stdout())
			}
		})
	}
}

// protojson varies its own spacing from build to build on purpose, so two
// builds of iq would print the same response differently — a stray second
// space after a colon — and neither output would diff against the other.
// The CLI re-indents it, which is what this pins.
func TestIAMJSONIsCanonicallyIndented(t *testing.T) {
	for _, args := range [][]string{
		{"iam", "list-roles"},
		{"iam", "get-role", "--name", "human"},
		{"sts", "get-caller-identity"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			stdout := runIAMOutput(t, args)
			compact := &bytes.Buffer{}
			if err := json.Compact(compact, []byte(stdout)); err != nil {
				t.Fatalf("stdout is not JSON: %v\n%s", err, stdout)
			}
			indented := &bytes.Buffer{}
			if err := json.Indent(indented, compact.Bytes(), "", "    "); err != nil {
				t.Fatal(err)
			}
			if stdout != indented.String()+"\n" {
				t.Fatalf("stdout\n%q\nis not four-space indented JSON:\n%q", stdout, indented.String()+"\n")
			}
		})
	}
}

func TestIAMListRolesOutputFormats(t *testing.T) {
	t.Run("json", func(t *testing.T) {
		stdout := runIAMOutput(t, []string{"iam", "list-roles", "--output", "json"})
		decoded := &iamv1.ListRolesResponse{}
		if err := protojson.Unmarshal([]byte(stdout), decoded); err != nil {
			t.Fatalf("stdout is not protojson: %v\n%s", err, stdout)
		}
		if len(decoded.GetRoles()) != 1 || decoded.GetRoles()[0].GetName() != "human" || decoded.GetRoles()[0].GetUrn() != "urn:motiveiq:iam:role/human" {
			t.Fatalf("decoded %v", decoded)
		}
	})
	t.Run("text", func(t *testing.T) {
		rows := textRows(t, runIAMOutput(t, []string{"iam", "list-roles", "--output", "text"}))
		if len(rows) != 1 {
			t.Fatalf("text rows %v, want one per role", rows)
		}
		if len(rows[0]) != 2 || rows[0][0] != "human" || rows[0][1] != "urn:motiveiq:iam:role/human" {
			t.Fatalf("row %v, want name and urn separated by a tab", rows[0])
		}
	})
	t.Run("table", func(t *testing.T) {
		title, headers, rows := parseIAMTable(t, runIAMOutput(t, []string{"iam", "list-roles", "--output", "table"}))
		if title != "iam:ListRoles" {
			t.Fatalf("title %q", title)
		}
		if strings.Join(headers, ",") != "name,urn" {
			t.Fatalf("headers %v", headers)
		}
		if len(rows) != 1 || rows[0][0] != "human" || rows[0][1] != "urn:motiveiq:iam:role/human" {
			t.Fatalf("rows %v, want one row per role", rows)
		}
	})
}

func TestIAMGetRoleOutputFormats(t *testing.T) {
	// Every format describes the same record, in the same order.
	fields := []string{"name", "urn", "max_session_duration_seconds", "attached_policy_urns", "create_time", "update_time", "assume_role_policy_document"}
	t.Run("json", func(t *testing.T) {
		stdout := runIAMOutput(t, []string{"iam", "get-role", "--name", "human", "--output", "json"})
		decoded := &iamv1.Role{}
		if err := protojson.Unmarshal([]byte(stdout), decoded); err != nil {
			t.Fatalf("stdout is not protojson: %v\n%s", err, stdout)
		}
		if decoded.GetName() != "human" || decoded.GetUrn() != "urn:motiveiq:iam:role/human" {
			t.Fatalf("decoded %v", decoded)
		}
	})
	t.Run("text", func(t *testing.T) {
		rows := textRows(t, runIAMOutput(t, []string{"iam", "get-role", "--name", "human", "--output", "text"}))
		if len(rows) != 1 {
			t.Fatalf("text rows %v, want the object on one line", rows)
		}
		if len(rows[0]) != len(fields) {
			t.Fatalf("row %v has %d values, want %d (%v)", rows[0], len(rows[0]), len(fields), fields)
		}
		if rows[0][0] != "human" || rows[0][1] != "urn:motiveiq:iam:role/human" {
			t.Fatalf("row %v", rows[0])
		}
	})
	t.Run("table", func(t *testing.T) {
		title, headers, rows := parseIAMTable(t, runIAMOutput(t, []string{"iam", "get-role", "--name", "human", "-o", "table"}))
		if title != "iam:GetRole" {
			t.Fatalf("title %q", title)
		}
		if strings.Join(headers, ",") != "field,value" {
			t.Fatalf("headers %v, want a field/value table for a single object", headers)
		}
		if len(rows) != len(fields) {
			t.Fatalf("rows %v, want one per field %v", rows, fields)
		}
		for i, field := range fields {
			if rows[i][0] != field {
				t.Fatalf("row %d is %v, want field %q", i, rows[i], field)
			}
		}
		if rows[0][1] != "human" || rows[1][1] != "urn:motiveiq:iam:role/human" {
			t.Fatalf("rows %v", rows)
		}
	})
}

// The human forms used to drop issuer_ca_bundle because a PEM bundle broke
// their key: value line shape. text and table now carry every field json
// does, flattened to one line and (in table) truncated to the column.
func TestIAMGetOIDCProviderCarriesCABundleInEveryFormat(t *testing.T) {
	args := []string{"iam", "get-oidc-provider", "--name", "hydra"}
	decoded := &iamv1.OIDCProvider{}
	if err := protojson.Unmarshal([]byte(runIAMOutput(t, append(args, "--output", "json"))), decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.GetIssuerCaBundle() == "" {
		t.Fatal("fixture provider has no CA bundle to render")
	}

	rows := textRows(t, runIAMOutput(t, append(args, "--output", "text")))
	if len(rows) != 1 || len(rows[0]) != 9 {
		t.Fatalf("text row %v, want the nine provider fields", rows)
	}
	if got := rows[0][8]; !strings.HasPrefix(got, "-----BEGIN CERTIFICATE-----") {
		t.Fatalf("issuer_ca_bundle %q", got)
	}

	_, _, tableRows := parseIAMTable(t, runIAMOutput(t, append(args, "--output", "table")))
	if len(tableRows) != 9 || tableRows[8][0] != "issuer_ca_bundle" {
		t.Fatalf("table rows %v", tableRows)
	}
	if !strings.HasSuffix(tableRows[8][1], iamTableEllipsis) {
		t.Fatalf("wide CA bundle %q was not truncated", tableRows[8][1])
	}
}

func TestIAMRejectsUnknownOutputFormat(t *testing.T) {
	fixture := newIAMTestFixture(t)
	code := fixture.command.Run(context.Background(), []string{"iam", "list-roles", "--output", "xml"})
	if code != 1 {
		t.Fatalf("exit code %d, want 1", code)
	}
	stderr := fixture.stderr()
	if !strings.Contains(stderr, "not a valid output format") {
		t.Fatalf("stderr %q", stderr)
	}
	for _, name := range []string{"json", "text", "table"} {
		if !strings.Contains(stderr, name) {
			t.Fatalf("stderr %q does not name %q", stderr, name)
		}
	}
	if fixture.iamDials != 0 || fixture.stsDials != 0 {
		t.Fatal("output validation must run before any dial")
	}
}

func TestIAMMissingCredentials(t *testing.T) {
	fixture := newIAMTestFixture(t)
	fixture.command.LoadSDKConfig = func(context.Context, string) (*motiveiq.Config, error) {
		return nil, errors.New("no web identity configured")
	}
	code := fixture.command.Run(context.Background(), []string{"iam", "list-roles"})
	if code != 1 {
		t.Fatalf("exit code %d, want 1", code)
	}
	if !strings.Contains(fixture.stderr(), "no web identity configured") {
		t.Fatalf("stderr %q", fixture.stderr())
	}
	if fixture.iamDials != 0 {
		t.Fatal("IAM client must not be dialed without a session")
	}
}

func TestIAMPermissionDeniedHint(t *testing.T) {
	fixture := newIAMTestFixture(t)
	fixture.iam.err = status.Error(codes.PermissionDenied, "principal is not allowed")
	code := fixture.command.Run(context.Background(), []string{"iam", "get-role", "--name", "human"})
	if code != 1 {
		t.Fatalf("exit code %d, want 1", code)
	}
	stderr := fixture.stderr()
	if !strings.Contains(stderr, "principal is not allowed") || !strings.Contains(stderr, "requires iam:GetRole") {
		t.Fatalf("stderr %q", stderr)
	}
}
