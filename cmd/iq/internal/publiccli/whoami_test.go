package publiccli

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/MotiveIQ/public/platform/iam/oauth"
)

// The token fields, in the order every format lists them.
var whoamiFields = []string{"subject", "audiences", "scopes", "expires_at"}

func runWhoami(t *testing.T, args ...string) string {
	t.Helper()
	fixture := newIAMTestFixture(t)
	token := testJWT(t, map[string]any{
		"sub": "fabian@motiveiq.com",
		"aud": []string{"https://platform.motiveiq.net"},
		"scp": []string{"iam:read", "deploy:read"},
		"exp": 1767225600,
	})
	fixture.command.LoadCredentials = func() (oauth.Credentials, error) {
		return oauth.Credentials{"access_token": token}, nil
	}
	if code := fixture.command.Run(context.Background(), append([]string{"whoami"}, args...)); code != 0 {
		t.Fatalf("whoami %v exit code %d, stderr: %s", args, code, fixture.stderr())
	}
	if fixture.iamDials != 0 || fixture.stsDials != 0 {
		t.Fatal("whoami must not touch the network")
	}
	return fixture.stdout()
}

func TestWhoamiDefaultOutputIsJSON(t *testing.T) {
	stdout := runWhoami(t)
	if !json.Valid([]byte(stdout)) {
		t.Fatalf("default stdout is not JSON: %q", stdout)
	}
	if explicit := runWhoami(t, "--output", "json"); explicit != stdout {
		t.Fatalf("--output json stdout %q, want the default's %q", explicit, stdout)
	}
}

// Every format describes one record, which includes the order its fields
// come in. A map would have sorted these alphabetically, listing the token
// one way in json and another in text and table.
func TestWhoamiJSONKeyOrderMatchesFields(t *testing.T) {
	decoder := json.NewDecoder(strings.NewReader(runWhoami(t)))
	if _, err := decoder.Token(); err != nil {
		t.Fatal(err)
	}
	keys := []string{}
	for decoder.More() {
		key, err := decoder.Token()
		if err != nil {
			t.Fatal(err)
		}
		keys = append(keys, key.(string))
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			t.Fatal(err)
		}
	}
	if strings.Join(keys, ",") != strings.Join(whoamiFields, ",") {
		t.Fatalf("json keys %v, want them in field order %v", keys, whoamiFields)
	}
}

func TestWhoamiOutputFormats(t *testing.T) {
	t.Run("json", func(t *testing.T) {
		var decoded struct {
			Subject   string   `json:"subject"`
			Audiences []string `json:"audiences"`
			Scopes    []string `json:"scopes"`
			ExpiresAt int64    `json:"expires_at"`
		}
		stdout := runWhoami(t, "--output", "json")
		if err := json.Unmarshal([]byte(stdout), &decoded); err != nil {
			t.Fatalf("stdout is not JSON: %v\n%s", err, stdout)
		}
		if decoded.Subject != "fabian@motiveiq.com" || decoded.ExpiresAt != 1767225600 {
			t.Fatalf("decoded %+v", decoded)
		}
		if strings.Join(decoded.Audiences, " ") != "https://platform.motiveiq.net" {
			t.Fatalf("decoded %+v", decoded)
		}
		if strings.Join(decoded.Scopes, " ") != "iam:read deploy:read" {
			t.Fatalf("decoded %+v", decoded)
		}
	})
	t.Run("text", func(t *testing.T) {
		rows := textRows(t, runWhoami(t, "--output", "text"))
		if len(rows) != 1 {
			t.Fatalf("text rows %v, want the token on one line", rows)
		}
		want := []string{"fabian@motiveiq.com", "https://platform.motiveiq.net", "iam:read deploy:read", "2026-01-01T00:00:00+00:00"}
		if strings.Join(rows[0], "\t") != strings.Join(want, "\t") {
			t.Fatalf("row %v, want %v", rows[0], want)
		}
	})
	t.Run("table", func(t *testing.T) {
		title, headers, rows := parseIAMTable(t, runWhoami(t, "--output", "table"))
		if title != "whoami" {
			t.Fatalf("title %q", title)
		}
		if strings.Join(headers, ",") != "field,value" {
			t.Fatalf("headers %v, want a field/value table for a single object", headers)
		}
		if len(rows) != len(whoamiFields) {
			t.Fatalf("rows %v, want one per field %v", rows, whoamiFields)
		}
		for i, field := range whoamiFields {
			if rows[i][0] != field {
				t.Fatalf("row %d is %v, want field %q", i, rows[i], field)
			}
		}
		if rows[0][1] != "fabian@motiveiq.com" || rows[3][1] != "2026-01-01T00:00:00+00:00" {
			t.Fatalf("rows %v", rows)
		}
	})
}

func TestWhoamiRejectsUnknownOutputFormat(t *testing.T) {
	fixture := newIAMTestFixture(t)
	code := fixture.command.Run(context.Background(), []string{"whoami", "--output", "xml"})
	if code != 1 {
		t.Fatalf("exit code %d, want 1", code)
	}
	if !strings.Contains(fixture.stderr(), "not a valid output format") {
		t.Fatalf("stderr %q", fixture.stderr())
	}
}

func TestWhoamiNotLoggedIn(t *testing.T) {
	fixture := newIAMTestFixture(t)
	fixture.command.LoadCredentials = func() (oauth.Credentials, error) {
		return nil, nil
	}
	code := fixture.command.Run(context.Background(), []string{"whoami"})
	if code != 1 {
		t.Fatalf("exit code %d, want 1", code)
	}
	if !strings.Contains(fixture.stderr(), "not logged in; run iq login") {
		t.Fatalf("stderr %q", fixture.stderr())
	}
}
