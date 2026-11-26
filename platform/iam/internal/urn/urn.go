// Package urn implements MotiveIQ resource names: parsing and canonical-form
// validation of concrete URNs, validation of URN patterns, and the v1 glob
// matcher used for both URN and action patterns.
//
// Grammar (DESIGN.md "Naming"):
//
//	urn:iq:<service>:<resource-type>/<resource-path>
//
// Service and resource-type are lowercase. Resource paths are case-sensitive.
// Parse accepts the previous namespace as an alias and requires canonical path encoding.
package urn

import (
	"fmt"
	"strings"

	"go.motiveiq.dev/lib/resourceurn"
)

const prefix = resourceurn.Prefix

// MaxBytes bounds every URN and URN pattern accepted anywhere in the system.
// Resource URNs are caller-controlled input to Cedar `like` evaluation, so
// their length is authorization cost: without a ceiling a multi-megabyte URN
// rides one Authorize call into every pattern match. Policy patterns carry the
// same bounded ceiling; this is the system-wide backstop.
// A maximum-length S3 bucket name and a 1024-byte key of slashes produce
// a 4180-byte canonical object URN.
const MaxBytes = 8 * 1024

// ServiceIAM is the URN service the IAM control plane owns. Roles, policies,
// and OIDC providers are the only MotiveIQ objects the control plane
// constructs from a caller-supplied name rather than accepting a whole URN
// (DESIGN.md decision 27); IAM and IAMName are that name↔URN bijection.
const ServiceIAM = "iam"

// ServiceSTS is the URN service STS-minted objects live under: assumed-role
// sessions and signing keys. Nothing is constructed from a caller-supplied
// name here, so there is no IAM-style constructor; the constant exists for
// the checks that must name the policy engine's own two services.
const ServiceSTS = "sts"

// MaxNameBytes caps a control-plane object name. A name is a single URN path
// segment, far shorter than a full URN (MaxBytes); 255 bytes is a generous
// single-label ceiling that still leaves the derived URN well under MaxBytes.
const MaxNameBytes = 255

// URN is a parsed, canonical MotiveIQ resource name.
type URN struct {
	Service      string
	ResourceType string
	// Path is the resource path, without the leading resource-type segment.
	Path string
	raw  string
}

// String returns the canonical textual representation.
func (u URN) String() string { return u.raw }

// Parse resolves the namespace of a concrete URN. It rejects oversized
// input (MaxBytes), wildcards, non-canonical forms, query strings,
// fragments, and trailing slashes.
func Parse(s string) (URN, error) {
	if len(s) > MaxBytes {
		return URN{}, fmt.Errorf("urn: %d bytes exceeds the %d-byte limit", len(s), MaxBytes)
	}
	s = resourceurn.Current(s)
	rest, ok := strings.CutPrefix(s, prefix)
	if !ok {
		return URN{}, fmt.Errorf("urn: %q does not start with %q", s, prefix)
	}
	service, resource, ok := strings.Cut(rest, ":")
	if !ok {
		return URN{}, fmt.Errorf("urn: %q missing resource portion", s)
	}
	if err := validateLabel(service); err != nil {
		return URN{}, fmt.Errorf("urn: service in %q: %w", s, err)
	}
	rtype, path, ok := strings.Cut(resource, "/")
	if !ok || path == "" {
		return URN{}, fmt.Errorf("urn: %q missing resource path", s)
	}
	if err := validateLabel(rtype); err != nil {
		return URN{}, fmt.Errorf("urn: resource type in %q: %w", s, err)
	}
	for _, seg := range strings.Split(path, "/") {
		if err := validateSegment(seg); err != nil {
			return URN{}, fmt.Errorf("urn: path in %q: %w", s, err)
		}
	}
	return URN{Service: service, ResourceType: rtype, Path: path, raw: s}, nil
}

// IAM constructs the canonical URN of an IAM-managed object of resourceType
// (role, policy, oidc-provider) named name:
// urn:iq:iam:<resourceType>/<name>. The control plane calls it to derive
// the server-owned URN from a caller-supplied name (DESIGN.md decision 27):
// the service and type are fixed by the endpoint, so only the name segment is
// caller input. resourceType must be a lowercase label; name must be a single
// path segment (ValidateName). The result equals Parse of the same string —
// IAM builds the canonical text and parses it, so the two paths cannot diverge.
func IAM(resourceType, name string) (URN, error) {
	if err := validateLabel(resourceType); err != nil {
		return URN{}, fmt.Errorf("iam urn: resource type: %w", err)
	}
	if err := ValidateName(name); err != nil {
		return URN{}, fmt.Errorf("iam urn: %w", err)
	}
	return Parse(prefix + ServiceIAM + ":" + resourceType + "/" + name)
}

// ParseIAM parses s as a canonical URN and additionally asserts the iam
// service and the given resourceType, so a role URN can never name a policy
// and vice versa. It validates a URN *reference* to an IAM object — used where
// one object refers to another by its whole URN (e.g. the policy_urn of an
// AttachRolePolicy) rather than by a bare name.
func ParseIAM(resourceType, s string) (URN, error) {
	u, err := Parse(s)
	if err != nil {
		return URN{}, err
	}
	if u.Service != ServiceIAM || u.ResourceType != resourceType {
		return URN{}, fmt.Errorf("urn: %q is not an urn:iq:%s:%s/... URN", s, ServiceIAM, resourceType)
	}
	return u, nil
}

// IAMName returns the name segment of a canonical IAM URN of resourceType: the
// inverse of IAM. The control plane uses it to render a stored, URN-keyed
// object's name back to callers at the API edge without re-parsing; s is
// assumed canonical (every stored IAM URN is, having been built by IAM).
func IAMName(s, resourceType string) string {
	return strings.TrimPrefix(resourceurn.Current(s), prefix+ServiceIAM+":"+resourceType+"/")
}

// ValidateService validates a URN service segment (a lowercase label), the
// identity of a ServiceDefinition registry entry.
func ValidateService(s string) error {
	return validateLabel(s)
}

// ValidateResourceType validates a URN resource-type segment (a lowercase
// label), as registered in a ServiceDefinition.
func ValidateResourceType(s string) error {
	return validateLabel(s)
}

// ValidateName validates a control-plane object name: exactly one URN path
// segment (DESIGN.md "Naming" — a name is a single resource-path segment). It
// applies the resource-path segment rules — unreserved characters plus
// canonical uppercase percent-escapes, no '/', no wildcards — under the
// MaxNameBytes cap. A valid name is exactly what IAM turns into a URN.
func ValidateName(name string) error {
	if len(name) > MaxNameBytes {
		return fmt.Errorf("name %d bytes exceeds the %d-byte limit", len(name), MaxNameBytes)
	}
	if err := validateSegment(name); err != nil {
		return fmt.Errorf("name: %w", err)
	}
	return nil
}

// ValidatePattern validates a URN pattern for use in a policy document. A
// pattern is matched against the entire canonical URN string; `*` is the only
// wildcard and may appear at any position (including across `:` and `/`).
// A bare "*" is valid.
func ValidatePattern(p string) error {
	if p == "" {
		return fmt.Errorf("urn pattern: empty")
	}
	if len(p) > MaxBytes {
		return fmt.Errorf("urn pattern: %d bytes exceeds the %d-byte limit", len(p), MaxBytes)
	}
	for i := 0; i < len(p); i++ {
		c := p[i]
		switch {
		case c == '*' || c == ':' || c == '/':
		case c == '%':
			var err error
			if i, err = validatePctAt(p, i); err != nil {
				return fmt.Errorf("urn pattern %q: %w", p, err)
			}
		case isUnreserved(c):
		default:
			return fmt.Errorf("urn pattern %q: invalid character %q", p, c)
		}
	}
	if p != "*" && !strings.HasPrefix(p, "urn:") && !strings.HasPrefix(p, "*") {
		return fmt.Errorf("urn pattern %q: must start with \"urn:\" or a wildcard", p)
	}
	return nil
}

// Glob reports whether s matches pattern, where `*` matches any sequence of
// characters (including `/` and `:`) and every other character matches
// literally. Matching is case-sensitive; callers that need case-insensitive
// matching (action names) must lowercase both sides first.
func Glob(pattern, s string) bool {
	pi, si := 0, 0
	star, mark := -1, 0
	for si < len(s) {
		switch {
		case pi < len(pattern) && pattern[pi] == '*':
			star, mark = pi, si
			pi++
		case pi < len(pattern) && pattern[pi] == s[si]:
			pi++
			si++
		case star >= 0:
			mark++
			pi, si = star+1, mark
		default:
			return false
		}
	}
	for pi < len(pattern) && pattern[pi] == '*' {
		pi++
	}
	return pi == len(pattern)
}

// validateLabel checks a service or resource-type label: lowercase ASCII
// letters, digits, and hyphens, starting with a letter.
func validateLabel(s string) error {
	if s == "" {
		return fmt.Errorf("empty label")
	}
	if s[0] < 'a' || s[0] > 'z' {
		return fmt.Errorf("label %q must start with a lowercase letter", s)
	}
	for i := 1; i < len(s); i++ {
		c := s[i]
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
			return fmt.Errorf("label %q contains invalid character %q", s, c)
		}
	}
	return nil
}

// validateSegment checks one resource-path segment: non-empty, unreserved
// characters plus canonical (uppercase hex) percent-escapes. Wildcards are
// rejected — concrete names never contain them.
func validateSegment(seg string) error {
	if seg == "" {
		return fmt.Errorf("empty path segment")
	}
	for i := 0; i < len(seg); i++ {
		c := seg[i]
		switch {
		case c == '%':
			var err error
			if i, err = validatePctAt(seg, i); err != nil {
				return err
			}
		case isUnreserved(c):
		case c == '*' || c == '?':
			return fmt.Errorf("segment %q contains wildcard %q", seg, c)
		default:
			return fmt.Errorf("segment %q contains invalid character %q (percent-encode it)", seg, c)
		}
	}
	return nil
}

// validatePctAt validates a percent-escape starting at index i and returns
// the index of its last byte. Only uppercase hex is canonical, and only
// reserved bytes may be escaped. Rejecting %65 for 'e' keeps each resource
// path unambiguous (DESIGN.md invariant 17).
func validatePctAt(s string, i int) (int, error) {
	if i+2 >= len(s) {
		return 0, fmt.Errorf("truncated percent-escape in %q", s)
	}
	hi, hiOK := unhex(s[i+1])
	lo, loOK := unhex(s[i+2])
	if !hiOK || !loOK {
		return 0, fmt.Errorf("non-canonical percent-escape in %q (uppercase hex required)", s)
	}
	if b := hi<<4 | lo; isUnreserved(b) {
		return 0, fmt.Errorf("percent-encoding of unreserved character %q in %q", string(rune(b)), s)
	}
	return i + 2, nil
}

// unhex decodes one canonical (uppercase) hex digit.
func unhex(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}

func isUnreserved(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' ||
		c == '-' || c == '.' || c == '_' || c == '~'
}
