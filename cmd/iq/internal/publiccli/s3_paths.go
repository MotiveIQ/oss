package publiccli

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	s3v1 "github.com/MotiveIQ/public/platform/s3/api/v1"
	"golang.org/x/text/unicode/norm"
)

type s3Location struct{ bucket, key, local string }

func (l s3Location) remote() bool { return l.bucket != "" }
func (l s3Location) stream() bool { return !l.remote() && l.local == "-" }
func (l s3Location) String() string {
	if l.remote() {
		return "s3://" + l.bucket + "/" + l.key
	}
	return l.local
}
func (l s3Location) prefix() s3Location {
	if l.remote() && l.key != "" && !strings.HasSuffix(l.key, "/") {
		l.key += "/"
	}
	return l
}
func (l s3Location) object() *s3v1.ObjectRef { return &s3v1.ObjectRef{Bucket: l.bucket, Key: l.key} }
func (l s3Location) child(relative string) s3Location {
	if l.remote() {
		l = l.prefix()
		l.key += relative
	} else {
		l.local = filepath.Join(l.local, filepath.FromSlash(relative))
	}
	return l
}

var s3BucketName = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$`)

func parseS3Location(raw string) (s3Location, error) {
	if raw == "" {
		return s3Location{}, fmt.Errorf("path must not be empty")
	}
	if !strings.HasPrefix(raw, "s3://") {
		if strings.Contains(raw, "://") {
			return s3Location{}, fmt.Errorf("expected a local path or s3://bucket/key: %q", raw)
		}
		return s3Location{local: raw}, nil
	}
	bucket, key, _ := strings.Cut(strings.TrimPrefix(raw, "s3://"), "/")
	if !s3BucketName.MatchString(bucket) {
		return s3Location{}, fmt.Errorf("invalid S3 bucket name %q", bucket)
	}
	if !utf8.ValidString(key) || len(key) > 1024 {
		return s3Location{}, fmt.Errorf("object key must be valid UTF-8 and at most 1024 bytes")
	}
	// An S3 URI is an opaque key, not a URL: never unescape or clean its path.
	return s3Location{bucket: bucket, key: key}, nil
}

type s3Filter struct {
	include bool
	pattern *regexp.Regexp
}
type s3FilterFlag struct {
	filters *[]s3Filter
	include bool
}

func (*s3FilterFlag) String() string { return "" }
func (*s3FilterFlag) Type() string   { return "pattern" }
func (f *s3FilterFlag) Set(pattern string) error {
	regex, err := s3Glob(pattern)
	if err != nil {
		return err
	}
	*f.filters = append(*f.filters, s3Filter{f.include, regex})
	return nil
}

// AWS-style fnmatch: '*' includes separators, and the last matching rule wins.
func s3Glob(pattern string) (*regexp.Regexp, error) {
	var b strings.Builder
	b.WriteString("(?s)^")
	runes := []rune(pattern)
	for i := 0; i < len(runes); i++ {
		switch runes[i] {
		case '*':
			b.WriteString(".*")
		case '?':
			b.WriteString(".")
		case '[':
			j := i + 1
			if j < len(runes) && runes[j] == '!' {
				j++
			}
			if j < len(runes) && runes[j] == ']' {
				j++
			}
			for j < len(runes) && runes[j] != ']' {
				j++
			}
			if j == len(runes) {
				b.WriteString(`\[`)
				continue
			}
			b.WriteByte('[')
			start := i + 1
			if runes[start] == '!' {
				b.WriteByte('^')
				start++
			}
			for _, c := range runes[start:j] {
				if c == '\\' || c == ']' || c == '^' {
					b.WriteByte('\\')
				}
				b.WriteRune(c)
			}
			b.WriteByte(']')
			i = j
		default:
			b.WriteString(regexp.QuoteMeta(string(runes[i])))
		}
	}
	b.WriteByte('$')
	rx, err := regexp.Compile(b.String())
	if err != nil {
		return nil, fmt.Errorf("invalid filter %q: %w", pattern, err)
	}
	return rx, nil
}
func (o s3Options) included(relative string) bool {
	yes := true
	for _, f := range o.filters {
		if f.pattern.MatchString(filepath.ToSlash(relative)) {
			yes = f.include
		}
	}
	return yes
}

type s3Entry struct {
	loc      s3Location
	relative string
	size     uint64
	modified time.Time
	metadata *s3v1.ObjectMetadata
	info     os.FileInfo
}

func (e s3Entry) directoryMarker() bool {
	return e.loc.remote() && e.size == 0 && strings.HasSuffix(e.loc.key, "/")
}

func (r *s3Run) objects(ctx context.Context, loc s3Location, delimiter string, visit func(*s3v1.ListObjectsResponse) error) error {
	token := ""
	seen := map[string]bool{}
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		page, err := r.client.ListObjects(ctx, &s3v1.ListObjectsRequest{Bucket: &s3v1.BucketRef{Name: loc.bucket}, Prefix: loc.key, Delimiter: delimiter, PageSize: r.options.pageSize, PageToken: token})
		if err != nil {
			return err
		}
		for _, m := range page.GetObjects() {
			if m == nil || m.GetObject().GetBucket() != loc.bucket || !strings.HasPrefix(m.GetObject().GetKey(), loc.key) {
				return fmt.Errorf("S3 listing returned an object outside the requested prefix")
			}
		}
		if err := visit(page); err != nil {
			return err
		}
		token = page.GetNextPageToken()
		if token == "" {
			return nil
		}
		if seen[token] {
			return fmt.Errorf("repeated object pagination token")
		}
		seen[token] = true
	}
}
func (r *s3Run) inventory(ctx context.Context, root s3Location, missingOK, source bool) ([]s3Entry, error) {
	var entries []s3Entry
	if root.remote() {
		root = root.prefix()
		seen := map[string]bool{}
		err := r.objects(ctx, root, "", func(page *s3v1.ListObjectsResponse) error {
			for _, m := range page.Objects {
				key := m.GetObject().GetKey()
				relative := strings.TrimPrefix(key, root.key)
				if seen[key] {
					return fmt.Errorf("duplicate object in listing: %q", key)
				}
				seen[key] = true
				if !r.options.included(relative) {
					continue
				}
				modified := time.Time{}
				if m.LastModified != nil {
					modified = m.LastModified.AsTime()
				}
				entries = append(entries, s3Entry{loc: s3Location{bucket: root.bucket, key: key}, relative: relative, size: m.ContentLength, modified: modified, metadata: m})
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	} else {
		st, err := os.Stat(root.local)
		if err != nil {
			if missingOK && os.IsNotExist(err) {
				return nil, nil
			}
			return nil, err
		}
		if !st.IsDir() {
			return nil, fmt.Errorf("%s is not a directory", root.local)
		}
		var walk func(string, []os.FileInfo) error
		walk = func(relative string, ancestors []os.FileInfo) error {
			if err := ctx.Err(); err != nil {
				return err
			}
			name := filepath.Join(root.local, relative)
			info, err := os.Lstat(name)
			if err != nil {
				return err
			}
			if info.Mode()&os.ModeSymlink != 0 {
				if !source || r.options.noFollow {
					if source {
						r.ignoredSources = append(r.ignoredSources, filepath.ToSlash(relative))
					}
					return nil
				}
				if r.rejectSourceSymlinks {
					return fmt.Errorf("mv does not follow symbolic-link sources: %s; use cp or --no-follow-symlinks", name)
				}
				info, err = os.Stat(name)
				if err != nil {
					return err
				}
			}
			if info.IsDir() {
				for _, parent := range ancestors {
					if os.SameFile(parent, info) {
						return fmt.Errorf("symbolic-link cycle at %s", name)
					}
				}
				children, err := os.ReadDir(name)
				if err != nil {
					return err
				}
				for _, child := range children {
					if err := walk(filepath.Join(relative, child.Name()), append(ancestors, info)); err != nil {
						return err
					}
				}
				return nil
			}
			rel := filepath.ToSlash(relative)
			if !r.options.included(rel) {
				return nil
			}
			if !info.Mode().IsRegular() {
				return fmt.Errorf("not a regular file: %s", name)
			}
			entries = append(entries, s3Entry{loc: s3Location{local: name}, relative: rel, size: uint64(info.Size()), modified: info.ModTime(), info: info})
			return nil
		}
		if err := walk("", nil); err != nil {
			return nil, err
		}
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].relative < entries[j].relative })
	return entries, nil
}

// Reject ambiguous translations instead of silently cleaning opaque object keys.
func s3LocalRelative(name string) error {
	if name == "" || !fs.ValidPath(name) || strings.ContainsAny(name, "\\\x00") || !filepath.IsLocal(filepath.FromSlash(name)) {
		return fmt.Errorf("object key cannot be safely mapped to a local file: %q", name)
	}
	return nil
}
func s3CheckLocalTargets(entries []s3Entry) error {
	seen := map[string]bool{}
	for _, e := range entries {
		if e.directoryMarker() {
			continue
		}
		if err := s3LocalRelative(e.relative); err != nil {
			return err
		}
		// macOS filesystems can alias canonically equivalent Unicode names.
		// Normalize only the collision key; preserve the actual object/path.
		name := strings.ToLower(norm.NFC.String(e.relative))
		if seen[name] {
			return fmt.Errorf("object keys collide on a case- or normalization-insensitive filesystem: %q", e.relative)
		}
		seen[name] = true
	}
	for name := range seen {
		for parent := filepath.ToSlash(filepath.Dir(name)); parent != "."; parent = filepath.ToSlash(filepath.Dir(parent)) {
			if seen[parent] {
				return fmt.Errorf("object key is both a file and a directory: %q", parent)
			}
		}
	}
	return nil
}
