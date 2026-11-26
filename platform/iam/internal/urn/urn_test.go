package urn

import (
	"strings"
	"testing"
)

func TestParse(t *testing.T) {
	valid := []string{
		"urn:iq:iam:role/payments-reconciler",
		"urn:iq:temporal:namespace/acme-prod",
		"urn:iq:ledger:account/payments/reconciliation",
		"urn:iq:sts:assumed-role/payments-reconciler/pod-01K8Y9",
		"urn:iq:git:repository/motiveiq/platform",
		"urn:iq:iam:role/Case.Sensitive_Path~ok",
		"urn:iq:iam:role/pct%2Fencoded", // %2F = '/': reserved, escapable
		"urn:iq:iam:role/pct%20space",   // %20 = ' ': reserved, escapable
		// Exactly MaxBytes is still accepted.
		"urn:iq:iam:role/" + strings.Repeat("x", MaxBytes-len("urn:iq:iam:role/")),
	}
	for _, s := range valid {
		u, err := Parse(s)
		if err != nil {
			t.Errorf("Parse(%q) unexpected error: %v", s, err)
			continue
		}
		if u.String() != s {
			t.Errorf("Parse(%q).String() = %q", s, u.String())
		}
	}

	invalid := map[string]string{
		"urn:iq:iam:role":               "no path",
		"urn:iq:iam:role/":              "empty path",
		"urn:iq:iam:role/x/":            "trailing slash",
		"urn:iq:iam:role//x":            "empty segment",
		"urn:iq:IAM:role/x":             "uppercase service",
		"urn:iq:iam:Role/x":             "uppercase type",
		"urn:iq:iam:role/pay*":          "wildcard",
		"urn:iq:iam:role/pay?q=1":       "query-ish wildcard char",
		"urn:iq:iam:role/a#b":           "fragment char",
		"urn:iq:iam:role/pct%2fencoded": "lowercase pct hex",
		"urn:iq:iam:role/pct%2":         "truncated pct",
		"urn:iq:iam:role/a b":           "space",
		"arn:motiveiq:iam:role/x":       "wrong scheme",
		"urn:other:iam:role/x":          "wrong org",
		"urn:iq:9iam:role/x":            "label starts with digit",
		// Over-encoded escapes of unreserved bytes are canonical aliases
		// (%65 spells 'e'); rejected, never normalized (invariant 17).
		"urn:iq:iam:role/pct%65ncoded":                     "percent-encoded unreserved letter",
		"urn:iq:iam:role/pct%41":                           "percent-encoded unreserved uppercase letter",
		"urn:iq:iam:role/pct%30":                           "percent-encoded unreserved digit",
		"urn:iq:iam:role/pct%7E":                           "percent-encoded unreserved tilde",
		"urn:iq:iam:role/" + strings.Repeat("x", MaxBytes): "over the byte limit",
	}
	for s, why := range invalid {
		if _, err := Parse(s); err == nil {
			t.Errorf("Parse(%q) succeeded; want error (%s)", s, why)
		}
	}
}

func TestParseSupportsEscapedS3KeyCeiling(t *testing.T) {
	prefix := "urn:iq:s3:object/" + strings.Repeat("b", 63) + "/"
	// Empty slash segments need both sentinels and separators.
	for _, key := range []string{
		strings.Repeat("%2F/", 1024) + "%2F",
		strings.Repeat("%25", 1024),
		strings.Repeat("%252F/", 256) + "%2F",
		strings.Repeat("%E9%9B%AA", 341) + "a",
	} {
		resource := prefix + key
		if _, err := Parse(resource); err != nil {
			t.Fatalf("Parse(%d-byte S3 resource): %v", len(resource), err)
		}
		if err := ValidatePattern(resource); err != nil {
			t.Fatalf("exact resource pattern: %v", err)
		}
	}
}

func TestValidateName(t *testing.T) {
	valid := []string{
		"payments-reconciler",
		"k8s-prod",
		"acme-workflow-access",
		"Case.Sensitive_Path~ok",
		"pct%2Fencoded", // reserved-byte escape is canonical
		strings.Repeat("x", MaxNameBytes),
	}
	for _, s := range valid {
		if err := ValidateName(s); err != nil {
			t.Errorf("ValidateName(%q) unexpected error: %v", s, err)
		}
	}
	invalid := map[string]string{
		"":                                  "empty",
		"a/b":                               "multi-segment (a name is one segment)",
		"/x":                                "leading slash",
		"x/":                                "trailing slash",
		"pay*":                              "wildcard",
		"a?b":                               "question wildcard",
		"a b":                               "space",
		"pct%2f":                            "lowercase percent hex",
		"pct%65ncoded":                      "percent-encoded unreserved letter",
		strings.Repeat("x", MaxNameBytes+1): "over the byte cap",
	}
	for in, why := range invalid {
		if err := ValidateName(in); err == nil {
			t.Errorf("ValidateName(%q) succeeded; want error (%s)", in, why)
		}
	}
}

func TestIAM(t *testing.T) {
	cases := []struct{ rtype, name, want string }{
		{"role", "payments-reconciler", "urn:iq:iam:role/payments-reconciler"},
		{"policy", "ledger-access", "urn:iq:iam:policy/ledger-access"},
		{"oidc-provider", "k8s-prod", "urn:iq:iam:oidc-provider/k8s-prod"},
	}
	for _, c := range cases {
		got, err := IAM(c.rtype, c.name)
		if err != nil {
			t.Errorf("IAM(%q, %q) error: %v", c.rtype, c.name, err)
			continue
		}
		if got.String() != c.want {
			t.Errorf("IAM(%q, %q) = %q, want %q", c.rtype, c.name, got.String(), c.want)
		}
		// IAM must equal a Parse round-trip of the same canonical string.
		parsed, err := Parse(c.want)
		if err != nil {
			t.Fatalf("Parse(%q): %v", c.want, err)
		}
		if got != parsed {
			t.Errorf("IAM(%q, %q) = %+v, want == Parse(%q) = %+v", c.rtype, c.name, got, c.want, parsed)
		}
		// IAMName is the inverse.
		if n := IAMName(c.want, c.rtype); n != c.name {
			t.Errorf("IAMName(%q, %q) = %q, want %q", c.want, c.rtype, n, c.name)
		}
	}

	invalid := []struct{ name, rtype, in string }{
		{"empty name", "role", ""},
		{"multi-segment name", "role", "a/b"},
		{"wildcard name", "role", "pay*"},
		{"non-canonical percent", "role", "pct%2f"},
		{"over-cap name", "role", strings.Repeat("x", MaxNameBytes+1)},
		{"uppercase type", "Role", "x"},
		{"empty type", "", "x"},
	}
	for _, tc := range invalid {
		if _, err := IAM(tc.rtype, tc.in); err == nil {
			t.Errorf("%s: IAM(%q, %q) succeeded; want error", tc.name, tc.rtype, tc.in)
		}
	}
}

func TestParseIAM(t *testing.T) {
	if _, err := ParseIAM("policy", "urn:iq:iam:policy/ledger-access"); err != nil {
		t.Errorf("valid iam policy urn rejected: %v", err)
	}
	invalid := []struct{ name, rtype, in string }{
		{"wrong type", "policy", "urn:iq:iam:role/x"},
		{"wrong service", "policy", "urn:iq:sts:policy/x"},
		{"non-canonical", "policy", "urn:iq:IAM:policy/x"},
		{"wildcard", "policy", "urn:iq:iam:policy/pay*"},
		{"empty", "policy", ""},
	}
	for _, tc := range invalid {
		if _, err := ParseIAM(tc.rtype, tc.in); err == nil {
			t.Errorf("%s: ParseIAM(%q, %q) succeeded; want error", tc.name, tc.rtype, tc.in)
		}
	}
}

func TestValidatePattern(t *testing.T) {
	valid := []string{
		"*",
		"urn:iq:temporal:namespace/acme-*",
		"urn:iq:temporal:*",
		"urn:iq:ledger:account/payments/*",
		"urn:iq:iam:role/exact-name",
		"*prod",
		"urn:iq:iam:role/pct%2Fencoded-*", // reserved-byte escape stays valid
	}
	for _, p := range valid {
		if err := ValidatePattern(p); err != nil {
			t.Errorf("ValidatePattern(%q) unexpected error: %v", p, err)
		}
	}
	invalid := []string{
		"",
		"urn:motiveiq:iam:role/example/*",
		"urn:iq:iam:role/a?",
		"urn:iq:iam:role/a b",
		"role/*",
		"urn:iq:iam:role/pct%65ncoded-*", // escape of unreserved 'e': canonical alias
		"urn:iq:iam:role/" + strings.Repeat("x", MaxBytes) + "*",
	}
	for _, p := range invalid {
		if err := ValidatePattern(p); err == nil {
			t.Errorf("ValidatePattern(%q) succeeded; want error", p)
		}
	}
}

func TestGlob(t *testing.T) {
	cases := []struct {
		pattern, s string
		want       bool
	}{
		{"*", "anything:at/all", true},
		{"urn:iq:temporal:namespace/acme-*", "urn:iq:temporal:namespace/acme-prod", true},
		{"urn:iq:temporal:namespace/acme*", "urn:iq:temporal:namespace/acme2", true},
		{"urn:iq:temporal:namespace/acme-*", "urn:iq:temporal:namespace/acmeX-prod", false},
		{"urn:iq:ledger:account/payments/*", "urn:iq:ledger:account/payments/a/b/c", true},
		{"urn:iq:temporal:*", "urn:iq:temporal:namespace/x", true},
		{"a*b*c", "aXXbYYc", true},
		{"a*b*c", "aXXbYY", false},
		{"exact", "exact", true},
		{"exact", "Exact", false},
		{"prefix", "prefixmore", false},
		{"**", "", true},
	}
	for _, c := range cases {
		if got := Glob(c.pattern, c.s); got != c.want {
			t.Errorf("Glob(%q, %q) = %v, want %v", c.pattern, c.s, got, c.want)
		}
	}
}

func TestAccountReferences(t *testing.T) {
	for _, tc := range []struct{ ref, account string }{
		{"urn:iq:iam:role/worker", ""},
		{"urn:iq:iam:7K3M5P9Q2R4T:role/worker", "7K3M5P9Q2R4T"},
		{"urn:iq:iam::service-definition/kms", ""},
	} {
		u, err := ParseReference(tc.ref)
		if err != nil || u.AccountID != tc.account || u.String() != tc.ref {
			t.Errorf("ParseReference(%q) = %v, %v", tc.ref, u, err)
		}
	}
	for _, ref := range []string{
		"urn:iq:iam::role/worker", "urn:iq:sts::assumed-role/worker/session", "urn:iq:kms::key/demo",
		"urn:iq:kms::service-definition/kms", "urn:iq:iam::service-definition/foo/bar", "urn:iq:iam:7K3M5P9Q2R4T:service-definition/kms",
		"urn:iq:iam:7K3M5P9Q2R4I:role/worker", "urn:iq:iam:7k3m5p9q2r4t:role/worker",
	} {
		if _, err := ParseReference(ref); err == nil {
			t.Errorf("accepted %q", ref)
		}
	}
}
