package urn

import (
	"go.motiveiq.dev/lib/resourceurn"

	"fmt"
	"math/rand"
	"strings"
	"testing"

	cedar "github.com/cedar-policy/cedar-go"
	"github.com/cedar-policy/cedar-go/types"
)

// TestGlobMatchesCedarLike is the drift guard between Glob (used for
// write-time linting) and Cedar `like` (used for actual evaluation): both
// must implement identical *-wildcard semantics. Deterministic seeded
// generation keeps failures reproducible.
func TestGlobMatchesCedarLike(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	alphabet := []byte("abc:/-")

	randText := func(n int) string {
		var b strings.Builder
		for range n {
			b.WriteByte(alphabet[rng.Intn(len(alphabet))])
		}
		return b.String()
	}
	randPattern := func(n int) string {
		var b strings.Builder
		for range n {
			if rng.Intn(4) == 0 {
				b.WriteByte('*')
			} else {
				b.WriteByte(alphabet[rng.Intn(len(alphabet))])
			}
		}
		return b.String()
	}

	for i := range 2000 {
		pattern := randPattern(1 + rng.Intn(10))
		var s string
		switch rng.Intn(3) {
		case 0:
			s = randText(rng.Intn(12))
		case 1:
			// Bias toward near-matches: the pattern with stars replaced.
			s = strings.ReplaceAll(pattern, "*", randText(rng.Intn(3)))
		default:
			s = strings.ReplaceAll(pattern, "*", "") + randText(rng.Intn(2))
		}

		got := Glob(pattern, s)
		want := cedarLike(t, pattern, s)
		if got != want {
			t.Fatalf("case %d: Glob(%q, %q) = %v, cedar like = %v", i, pattern, s, got, want)
		}
	}
}

// cedarLike evaluates `context.s like <pattern>` with the real engine.
func cedarLike(t *testing.T, pattern, s string) bool {
	t.Helper()
	text := fmt.Sprintf(`permit (principal, action, resource) when { context.s like "%s" };`,
		pattern) // alphabet contains nothing needing escape
	ps, err := cedar.NewPolicySetFromBytes("p.cedar", []byte(text))
	if err != nil {
		t.Fatalf("pattern %q failed to parse as cedar like: %v", pattern, err)
	}
	uid := types.NewEntityUID("T", "x")
	decision, _ := cedar.Authorize(ps, types.EntityMap{}, cedar.Request{
		Principal: uid, Action: types.NewEntityUID("Action", "a"), Resource: uid,
		Context: types.NewRecord(types.RecordMap{"s": types.String(s)}),
	})
	return decision == cedar.Allow
}

func FuzzParse(f *testing.F) {
	for _, seed := range []string{
		"urn:motiveiq:iam:role/payments-reconciler",
		"urn:motiveiq:ledger:account/payments/reconciliation",
		"urn:motiveiq:iam:role/pct%2Fencoded",
		"urn:motiveiq:iam:role/pct%65ncoded",
		"urn:motiveiq:iam:role/",
		"urn:motiveiq:IAM:role/x",
		"urn:motiveiq:iam:role/a*",
		"::://///%%%",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, s string) {
		u, err := Parse(s)
		if err != nil {
			return
		}
		// Canonical round-trip: successful parses reproduce their input
		// exactly and re-parse to the same components.
		if u.String() != resourceurn.Current(s) {
			t.Fatalf("Parse(%q).String() = %q", s, u.String())
		}
		u2, err := Parse(u.String())
		if err != nil || u2 != u {
			t.Fatalf("re-parse of %q diverged: %+v vs %+v (%v)", s, u, u2, err)
		}
		if strings.ContainsAny(s, "*?") {
			t.Fatalf("Parse accepted wildcard in %q", s)
		}
	})
}

func FuzzGlob(f *testing.F) {
	f.Add("urn:motiveiq:temporal:namespace/acme-*", "urn:motiveiq:temporal:namespace/acme-prod")
	f.Add("*", "")
	f.Add("a*b*c", "abc")
	f.Fuzz(func(t *testing.T, pattern, s string) {
		matched := Glob(pattern, s) // must not panic or hang
		// Widening a pattern can never unmatch it.
		if matched {
			if !Glob(pattern+"*", s) || !Glob("*"+pattern, s) {
				t.Fatalf("widening %q unmatched %q", pattern, s)
			}
		}
		// A literal pattern matches exactly itself.
		if !strings.Contains(s, "*") && pattern == s && !matched {
			t.Fatalf("identity match failed for %q", s)
		}
	})
}
