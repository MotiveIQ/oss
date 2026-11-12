package publiccli

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protojson"

	iamv1 "github.com/MotiveIQ/public/platform/iam/api/v1"
)

// The identity fields, in the order every format lists them.
var stsCallerIdentityFields = []string{"session_id", "session_urn", "role_urn", "session_name", "expire_time"}

func TestSTSGetCallerIdentityDefaultOutputIsJSON(t *testing.T) {
	defaultFixture := newIAMTestFixture(t)
	if code := defaultFixture.command.Run(context.Background(), []string{"sts", "get-caller-identity"}); code != 0 {
		t.Fatalf("exit code %d, stderr: %s", code, defaultFixture.stderr())
	}
	if !json.Valid([]byte(defaultFixture.stdout())) {
		t.Fatalf("default stdout is not JSON: %q", defaultFixture.stdout())
	}
	jsonFixture := newIAMTestFixture(t)
	if code := jsonFixture.command.Run(context.Background(), []string{"sts", "get-caller-identity", "--output", "json"}); code != 0 {
		t.Fatalf("--output json exit code %d, stderr: %s", code, jsonFixture.stderr())
	}
	if jsonFixture.stdout() != defaultFixture.stdout() {
		t.Fatalf("--output json stdout %q, want the default's %q", jsonFixture.stdout(), defaultFixture.stdout())
	}
}

func TestSTSGetCallerIdentityOutputFormats(t *testing.T) {
	t.Run("json", func(t *testing.T) {
		stdout := runIAMOutput(t, []string{"sts", "get-caller-identity", "--output", "json"})
		decoded := &iamv1.GetCallerIdentityResponse{}
		if err := protojson.Unmarshal([]byte(stdout), decoded); err != nil {
			t.Fatalf("stdout is not protojson: %v\n%s", err, stdout)
		}
		if decoded.GetSessionId() != "session_123" || decoded.GetSessionName() != "fabian" {
			t.Fatalf("decoded %v", decoded)
		}
		if decoded.GetSessionUrn() != "urn:motiveiq:sts:assumed-role/human/fabian" || decoded.GetRoleUrn() != "urn:motiveiq:iam:role/human" {
			t.Fatalf("decoded %v", decoded)
		}
		if decoded.GetExpireTime().AsTime() != time.Unix(1767225600, 0).UTC() {
			t.Fatalf("expire time %v", decoded.GetExpireTime().AsTime())
		}
	})
	t.Run("text", func(t *testing.T) {
		rows := textRows(t, runIAMOutput(t, []string{"sts", "get-caller-identity", "--output", "text"}))
		if len(rows) != 1 {
			t.Fatalf("text rows %v, want the identity on one line", rows)
		}
		want := []string{"session_123", "urn:motiveiq:sts:assumed-role/human/fabian", "urn:motiveiq:iam:role/human", "fabian", "2026-01-01T00:00:00+00:00"}
		if strings.Join(rows[0], "\t") != strings.Join(want, "\t") {
			t.Fatalf("row %v, want %v", rows[0], want)
		}
	})
	t.Run("table", func(t *testing.T) {
		title, headers, rows := parseIAMTable(t, runIAMOutput(t, []string{"sts", "get-caller-identity", "--output", "table"}))
		if title != "sts:GetCallerIdentity" {
			t.Fatalf("title %q", title)
		}
		if strings.Join(headers, ",") != "field,value" {
			t.Fatalf("headers %v, want a field/value table for a single object", headers)
		}
		if len(rows) != len(stsCallerIdentityFields) {
			t.Fatalf("rows %v, want one per field %v", rows, stsCallerIdentityFields)
		}
		for i, field := range stsCallerIdentityFields {
			if rows[i][0] != field {
				t.Fatalf("row %d is %v, want field %q", i, rows[i], field)
			}
		}
		if rows[1][1] != "urn:motiveiq:sts:assumed-role/human/fabian" || rows[4][1] != "2026-01-01T00:00:00+00:00" {
			t.Fatalf("rows %v", rows)
		}
	})
}

func TestSTSGetCallerIdentity(t *testing.T) {
	fixture := newIAMTestFixture(t)
	code := fixture.command.Run(context.Background(), []string{"sts", "get-caller-identity"})
	if code != 0 {
		t.Fatalf("exit code %d, stderr: %s", code, fixture.stderr())
	}
	if fixture.sts.callerCalls != 1 {
		t.Fatalf("GetCallerIdentity calls: %d", fixture.sts.callerCalls)
	}
	if len(fixture.loadedRoles) != 1 || fixture.loadedRoles[0] != IAMHumanRoleURN {
		t.Fatalf("loaded roles = %v, want %q", fixture.loadedRoles, IAMHumanRoleURN)
	}
	if fixture.stsDials != 1 || fixture.iamDials != 0 {
		t.Fatalf("client construction STS/IAM = %d/%d", fixture.stsDials, fixture.iamDials)
	}
}

func TestSTSRejectsUnknownOutputFormat(t *testing.T) {
	fixture := newIAMTestFixture(t)
	code := fixture.command.Run(context.Background(), []string{"sts", "get-caller-identity", "--output", "xml"})
	if code != 1 {
		t.Fatalf("exit code %d, want 1", code)
	}
	if !strings.Contains(fixture.stderr(), "not a valid output format") {
		t.Fatalf("stderr %q", fixture.stderr())
	}
	if fixture.stsDials != 0 {
		t.Fatal("output validation must run before any dial")
	}
}
