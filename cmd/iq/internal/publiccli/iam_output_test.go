package publiccli

import (
	"strings"
	"testing"
	"unicode/utf8"

	iamv1 "github.com/MotiveIQ/public/platform/iam/api/v1"
)

// parseIAMTable checks that the caption, borders and cells occupy one frame.
func parseIAMTable(t *testing.T, out string) (title string, headers []string, rows [][]string) {
	t.Helper()
	lines := strings.Split(strings.TrimSuffix(out, "\n"), "\n")
	if len(lines) < 6 {
		t.Fatalf("incomplete table:\n%s", out)
	}
	width := utf8.RuneCountInString(lines[0])
	for _, line := range lines {
		if utf8.RuneCountInString(line) != width {
			t.Fatalf("line %q does not fit the %d-column frame:\n%s", line, width, out)
		}
	}
	if strings.Trim(lines[0], "-") != "" || lines[2] != lines[0] || lines[4] != lines[len(lines)-1] {
		t.Fatalf("invalid frame:\n%s", out)
	}
	title = strings.TrimSpace(strings.Trim(lines[1], "|"))
	// Split by border offsets rather than by |, which may occur in values.
	var borders []int
	for i, r := range []rune(lines[4]) {
		if r == '+' {
			borders = append(borders, i)
		} else if r != '-' {
			t.Fatalf("invalid column rule: %q", lines[4])
		}
	}
	split := func(line string) []string {
		runes := []rune(line)
		var cells []string
		for i := 1; i < len(borders); i++ {
			start, end := borders[i-1], borders[i]
			if runes[start] != '|' || runes[end] != '|' {
				t.Fatalf("misaligned cell: %q", line)
			}
			cells = append(cells, strings.TrimSpace(string(runes[start+1:end])))
		}
		return cells
	}
	headers = split(lines[3])
	for _, line := range lines[5 : len(lines)-1] {
		rows = append(rows, split(line))
	}
	return title, headers, rows
}

// textRows splits AWS-style text output: one record per line, values
// separated by tabs, no headers.
func textRows(t *testing.T, out string) [][]string {
	t.Helper()
	if out == "" {
		return nil
	}
	if !strings.HasSuffix(out, "\n") {
		t.Fatalf("text output does not end in a newline: %q", out)
	}
	rows := [][]string{}
	for _, line := range strings.Split(strings.TrimSuffix(out, "\n"), "\n") {
		rows = append(rows, strings.Split(line, "\t"))
	}
	return rows
}

func TestIAMOutputFormatValidation(t *testing.T) {
	for _, output := range []string{outputJSON, outputYAML, outputText, outputTable} {
		if err := validateIAMOutput(output); err != nil {
			t.Fatalf("validateIAMOutput(%q) = %v", output, err)
		}
	}
	// The empty string is not a format: --output defaults to json before
	// validation runs, so reaching here means the user passed --output "".
	for _, output := range []string{"", "xml", "TABLE"} {
		err := validateIAMOutput(output)
		if err == nil {
			t.Fatalf("validateIAMOutput(%q) accepted an unknown format", output)
		}
		for _, name := range []string{"json", "text", "table"} {
			if !strings.Contains(err.Error(), name) {
				t.Fatalf("error %q does not name %q", err, name)
			}
		}
	}
}

func TestIAMTableTruncatesWideValues(t *testing.T) {
	wide := strings.Repeat("urn:motiveiq:iam:role/", 20)
	tests := []struct {
		name  string
		field string
		view  iamView
	}{
		{"role trust policy", "assume_role_policy_document", iamRoleView(&iamv1.Role{AssumeRolePolicyDocument: wide})},
		{"managed policy", "document_json", iamPolicyView(&iamv1.Policy{DefaultVersion: &iamv1.PolicyVersion{DocumentJson: wide}})},
		{"OIDC CA bundle", "issuer_ca_bundle", iamOIDCProviderView(&iamv1.OIDCProvider{IssuerCaBundle: wide})},
		{"resource policy", "document_json", iamResourcePolicyView(&iamv1.ResourcePolicy{DocumentJson: wide})},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			builder := &strings.Builder{}
			writeIAMTable(builder, "iam:Get", test.view)

			_, _, rows := parseIAMTable(t, builder.String())
			values := make(map[string]string, len(rows))
			for _, row := range rows {
				values[row[0]] = row[1]
			}
			value := values[test.field]
			if utf8.RuneCountInString(value) != iamTableCellWidth {
				t.Fatalf("cell is %d wide, want exactly %d — truncation is at a fixed width", utf8.RuneCountInString(value), iamTableCellWidth)
			}
			if !strings.HasSuffix(value, iamTableEllipsis) || !strings.HasPrefix(wide, strings.TrimSuffix(value, iamTableEllipsis)) {
				t.Fatalf("wide value %q is not the head of the original with an ellipsis", value)
			}
		})
	}
}

func TestIAMTablePreservesWideIdentifiers(t *testing.T) {
	name := strings.Repeat("n", 255)
	urn := "urn:motiveiq:iam:role/" + strings.Repeat("u", 300)
	role := &iamv1.Role{Name: name, Urn: urn}

	t.Run("object", func(t *testing.T) {
		builder := &strings.Builder{}
		writeIAMTable(builder, "iam:GetRole", iamRoleView(role))

		_, _, rows := parseIAMTable(t, builder.String())
		values := make(map[string]string, len(rows))
		for _, row := range rows {
			values[row[0]] = row[1]
		}
		if values["name"] != name {
			t.Fatalf("name = %q, want the complete %d-rune identifier", values["name"], utf8.RuneCountInString(name))
		}
		if values["urn"] != urn {
			t.Fatalf("urn = %q, want the complete %d-rune identifier", values["urn"], utf8.RuneCountInString(urn))
		}
	})

	t.Run("list", func(t *testing.T) {
		builder := &strings.Builder{}
		writeIAMTable(builder, "iam:ListRoles", iamRoleListView(&iamv1.ListRolesResponse{Roles: []*iamv1.Role{role}}))

		_, _, rows := parseIAMTable(t, builder.String())
		if len(rows) != 1 || len(rows[0]) != 2 {
			t.Fatalf("rows = %v, want one row with name and URN", rows)
		}
		if rows[0][0] != name || rows[0][1] != urn {
			t.Fatalf("row = %q, want complete identifiers %q and %q", rows[0], name, urn)
		}
	})
}

// A PEM bundle or an indented policy document carries newlines, and text
// separates its values with tabs. Either character reaching the output
// would split one record across lines or invent a column.
func TestIAMOutputFlattensMultilineValues(t *testing.T) {
	view := iamObjectView([]iamField{
		{"name", "hydra"},
		{"issuer_ca_bundle", "-----BEGIN CERTIFICATE-----\nMIIB\ttab\r\n-----END CERTIFICATE-----"},
	})

	text := &strings.Builder{}
	writeIAMText(text, view)
	rows := textRows(t, text.String())
	if len(rows) != 1 || len(rows[0]) != 2 {
		t.Fatalf("text rows %v, want one record of two values", rows)
	}

	table := &strings.Builder{}
	writeIAMTable(table, "iam:GetOIDCProvider", view)
	if _, _, tableRows := parseIAMTable(t, table.String()); len(tableRows) != 2 {
		t.Fatalf("table rows %v, want one per field", tableRows)
	}
}

// The AWS CLI prints nothing at all when a list comes back empty.
func TestIAMEmptyListPrintsNothing(t *testing.T) {
	view := iamListView([]string{"name", "urn"}, nil)
	for name, write := range map[string]func(*strings.Builder){
		"text":  func(b *strings.Builder) { writeIAMText(b, view) },
		"table": func(b *strings.Builder) { writeIAMTable(b, "iam:ListRoles", view) },
	} {
		builder := &strings.Builder{}
		write(builder)
		if builder.String() != "" {
			t.Fatalf("%s output for an empty list: %q", name, builder.String())
		}
	}
}

// A caption wider than the columns widens the rules under it, so the
// frame still reads as one table rather than a caption with a stub of a
// rule beneath it.
func TestIAMTableFitsTitleWiderThanColumns(t *testing.T) {
	builder := &strings.Builder{}
	writeIAMTable(builder, "sts:GetCallerIdentity", iamListView([]string{"a"}, [][]string{{"b"}}))
	out := builder.String()
	title, _, _ := parseIAMTable(t, out)
	if title != "sts:GetCallerIdentity" {
		t.Fatalf("title %q", title)
	}
	caption := utf8.RuneCountInString(strings.SplitN(out, "\n", 2)[0])
	rule := strings.Split(strings.TrimSuffix(out, "\n"), "\n")[2]
	if got := utf8.RuneCountInString(rule); got < caption {
		t.Fatalf("rule %q is %d wide, want at least the caption's %d", rule, got, caption)
	}
}

// Pin the AWS-style ASCII frame and column alignment.
func TestIAMTableFrame(t *testing.T) {
	builder := &strings.Builder{}
	writeIAMTable(builder, "iam:ListRoles", iamListView([]string{"name", "urn"}, [][]string{
		{"human", "urn:motiveiq:iam:role/human"},
		{"prod-temporal--ui", "urn:motiveiq:iam:role/prod-temporal--ui"},
	}))
	want := strings.Join([]string{
		"---------------------------------------------------------------",
		"|                        iam:ListRoles                        |",
		"---------------------------------------------------------------",
		"| name              | urn                                     |",
		"+-------------------+-----------------------------------------+",
		"| human             | urn:motiveiq:iam:role/human             |",
		"| prod-temporal--ui | urn:motiveiq:iam:role/prod-temporal--ui |",
		"+-------------------+-----------------------------------------+",
		"",
	}, "\n")
	if builder.String() != want {
		t.Fatalf("table\n%s\nwant\n%s", builder.String(), want)
	}
}
