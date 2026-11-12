package publiccli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	motiveiq "github.com/MotiveIQ/public/platform/iam/sdk"
	s3v1 "github.com/MotiveIQ/public/platform/s3/api/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type fakeS3 struct {
	*s3v1.Client
	objects                       map[string][]byte
	metadata                      map[string]*s3v1.ObjectMetadata
	puts, deletes                 []string
	gets                          []*s3v1.GetObjectRequest
	lists                         []*s3v1.ListObjectsRequest
	getError, putError, listError error
	failPage                      int
	commits                       int
	created                       *s3v1.CreateBucketRequest
	removed                       *s3v1.DeleteBucketRequest
	mutationState                 string
	onSend                        func(*s3v1.PutObjectRequest)
}

func newFakeS3() *fakeS3 {
	f := &fakeS3{objects: map[string][]byte{}, metadata: map[string]*s3v1.ObjectMetadata{}}
	f.Client = s3v1.NewFromConfig(&fakeS3Transport{owner: f})
	return f
}

// Use the real Upload/Download helpers against a fake transport so CLI safety
// tests also cover their EOF, signed completion, and stream validation behavior.
type fakeS3Transport struct {
	grpc.ClientConnInterface
	owner *fakeS3
}

func (f *fakeS3Transport) GRPCClientConn(string, string, string, string) grpc.ClientConnInterface {
	return f
}
func (f *fakeS3Transport) SignedUploadClientStream(ctx context.Context, _, _, _, _, method string, _ ...grpc.CallOption) (grpc.ClientStream, error) {
	if method != s3v1.DataPlane_PutObject_FullMethodName {
		return nil, fmt.Errorf("unexpected upload method: %s", method)
	}
	return &fakeS3Upload{ctx: ctx, owner: f.owner}, nil
}
func (f *fakeS3Transport) NewStream(_ context.Context, _ *grpc.StreamDesc, method string, _ ...grpc.CallOption) (grpc.ClientStream, error) {
	if method != s3v1.DataPlane_GetObject_FullMethodName {
		return nil, fmt.Errorf("unexpected stream method: %s", method)
	}
	return &fakeS3Download{owner: f.owner}, nil
}
func (f *fakeS3) add(bucket, key string, body []byte) *s3v1.ObjectMetadata {
	id := bucket + "/" + key
	f.objects[id] = body
	m := &s3v1.ObjectMetadata{Object: &s3v1.ObjectRef{Bucket: bucket, Key: key}, ContentLength: uint64(len(body)), Etag: "etag-" + key, ContentType: "application/test", LastModified: timestamppb.New(time.Unix(1700000000, 0))}
	f.metadata[id] = m
	return m
}
func (f *fakeS3) HeadObject(_ context.Context, q *s3v1.HeadObjectRequest, _ ...grpc.CallOption) (*s3v1.HeadObjectResponse, error) {
	m, ok := f.metadata[q.Object.Bucket+"/"+q.Object.Key]
	if !ok {
		return nil, status.Error(codes.NotFound, "missing")
	}
	return &s3v1.HeadObjectResponse{Metadata: proto.Clone(m).(*s3v1.ObjectMetadata)}, nil
}
func (f *fakeS3) ListObjects(_ context.Context, q *s3v1.ListObjectsRequest, _ ...grpc.CallOption) (*s3v1.ListObjectsResponse, error) {
	f.lists = append(f.lists, proto.Clone(q).(*s3v1.ListObjectsRequest))
	start, _ := strconv.Atoi(q.PageToken)
	if f.listError != nil && start >= f.failPage {
		return nil, f.listError
	}
	var keys []string
	for key, m := range f.metadata {
		if m.Object.Bucket == q.Bucket.Name && strings.HasPrefix(m.Object.Key, q.Prefix) {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	end := min(start+int(q.PageSize), len(keys))
	page := &s3v1.ListObjectsResponse{}
	prefixes := map[string]bool{}
	for _, key := range keys[start:end] {
		m := f.metadata[key]
		rest := strings.TrimPrefix(m.Object.Key, q.Prefix)
		if q.Delimiter != "" && strings.Contains(rest, q.Delimiter) {
			part, _, _ := strings.Cut(rest, q.Delimiter)
			prefix := q.Prefix + part + q.Delimiter
			if !prefixes[prefix] {
				page.CommonPrefixes = append(page.CommonPrefixes, prefix)
				prefixes[prefix] = true
			}
			continue
		}
		page.Objects = append(page.Objects, proto.Clone(m).(*s3v1.ObjectMetadata))
	}
	if end < len(keys) {
		page.NextPageToken = strconv.Itoa(end)
	}
	return page, nil
}

type fakeS3Download struct {
	grpc.ClientStream
	owner    *fakeS3
	frames   []*s3v1.GetObjectResponse
	terminal error
}

func (s *fakeS3Download) RecvMsg(message any) error {
	if len(s.frames) == 0 {
		if s.terminal != nil {
			return s.terminal
		}
		return io.EOF
	}
	m := s.frames[0]
	s.frames = s.frames[1:]
	proto.Merge(message.(*s3v1.GetObjectResponse), m)
	return nil
}
func (s *fakeS3Download) CloseSend() error { return nil }
func (s *fakeS3Download) SendMsg(message any) error {
	f := s.owner
	q := message.(*s3v1.GetObjectRequest)
	f.gets = append(f.gets, proto.Clone(q).(*s3v1.GetObjectRequest))
	id := q.Object.Bucket + "/" + q.Object.Key
	m := f.metadata[id]
	if m == nil {
		return status.Error(codes.NotFound, "missing")
	}
	if q.GetConditions().GetIfMatch() != "" && q.Conditions.IfMatch != m.Etag {
		return status.Error(codes.FailedPrecondition, "changed")
	}
	s.terminal = f.getError
	s.frames = []*s3v1.GetObjectResponse{{Frame: &s3v1.GetObjectResponse_Metadata{Metadata: proto.Clone(m).(*s3v1.ObjectMetadata)}}}
	for data := f.objects[id]; len(data) > 0; {
		n := min(len(data), 64*1024)
		s.frames = append(s.frames, &s3v1.GetObjectResponse{Frame: &s3v1.GetObjectResponse_Data{Data: data[:n]}})
		data = data[n:]
	}
	return nil
}

type fakeS3Upload struct {
	grpc.ClientStream
	ctx    context.Context
	owner  *fakeS3
	header *s3v1.PutObjectHeader
	body   []byte
	result *s3v1.ObjectMetadata
}

func (s *fakeS3Upload) SendMsg(message any) error {
	var q *s3v1.PutObjectRequest
	switch m := message.(type) {
	case *s3v1.PutObjectHeader:
		q = &s3v1.PutObjectRequest{Frame: &s3v1.PutObjectRequest_Header{Header: m}}
	case *s3v1.PutObjectRequest:
		q = m
	default:
		return fmt.Errorf("unexpected upload message: %T", message)
	}
	if s.owner.onSend != nil {
		s.owner.onSend(q)
	}
	if s.owner.putError != nil {
		return s.owner.putError
	}
	if err := s.ctx.Err(); err != nil {
		return err
	}
	if h := q.GetHeader(); h != nil {
		if s.header != nil {
			return fmt.Errorf("duplicate header")
		}
		s.header = proto.Clone(h).(*s3v1.PutObjectHeader)
		return nil
	}
	if len(q.GetData()) > 64*1024 {
		return fmt.Errorf("chunk exceeds limit")
	}
	s.body = append(s.body, q.GetData()...)
	return nil
}
func (s *fakeS3Upload) CloseSend() error {
	if err := s.ctx.Err(); err != nil {
		return err
	}
	if s.header == nil || s.header.ContentLength == nil || *s.header.ContentLength != uint64(len(s.body)) {
		return fmt.Errorf("incomplete upload")
	}
	s.owner.commits++
	s.owner.puts = append(s.owner.puts, s.header.Bucket+"/"+s.header.Key)
	m := s.owner.add(s.header.Bucket, s.header.Key, s.body)
	m.ContentType = s.header.ContentType
	m.ContentEncoding = s.header.ContentEncoding
	m.ContentDisposition = s.header.ContentDisposition
	m.Metadata = s.header.Metadata
	m.CacheControl = s.header.CacheControl
	s.result = m
	return nil
}
func (s *fakeS3Upload) RecvMsg(message any) error {
	if s.owner.putError != nil {
		return s.owner.putError
	}
	message.(*s3v1.PutObjectResponse).Metadata = s.result
	return nil
}
func (f *fakeS3) DeleteObject(_ context.Context, q *s3v1.DeleteObjectRequest, _ ...grpc.CallOption) (*s3v1.DeleteObjectResponse, error) {
	id := q.Object.Bucket + "/" + q.Object.Key
	if q.GetConditions().GetIfMatch() != "" && q.Conditions.IfMatch != f.metadata[id].Etag {
		return nil, status.Error(codes.FailedPrecondition, "changed")
	}
	f.deletes = append(f.deletes, id)
	delete(f.objects, id)
	delete(f.metadata, id)
	return &s3v1.DeleteObjectResponse{}, nil
}
func (f *fakeS3) ListBuckets(_ context.Context, q *s3v1.ListBucketsRequest, _ ...grpc.CallOption) (*s3v1.ListBucketsResponse, error) {
	if q.PageToken == "" {
		return &s3v1.ListBucketsResponse{Buckets: []*s3v1.Bucket{{Name: "zzz", CreateTime: timestamppb.Now()}}, NextPageToken: "next"}, nil
	}
	return &s3v1.ListBucketsResponse{Buckets: []*s3v1.Bucket{{Name: "aaa", CreateTime: timestamppb.Now()}}}, nil
}
func (f *fakeS3) CreateBucket(_ context.Context, q *s3v1.CreateBucketRequest, _ ...grpc.CallOption) (*s3v1.CreateBucketResponse, error) {
	f.created = q
	return &s3v1.CreateBucketResponse{Bucket: &s3v1.Bucket{Name: q.Name, Id: "immutable-id"}}, nil
}
func (f *fakeS3) GetBucket(_ context.Context, q *s3v1.GetBucketRequest, _ ...grpc.CallOption) (*s3v1.HeadBucketResponse, error) {
	return &s3v1.HeadBucketResponse{Bucket: &s3v1.Bucket{Name: q.Bucket.Name, Id: "immutable-id", Revision: 7, Ready: true}}, nil
}
func (f *fakeS3) DeleteBucket(_ context.Context, q *s3v1.DeleteBucketRequest, _ ...grpc.CallOption) (*s3v1.DeleteBucketResponse, error) {
	f.removed = q
	return &s3v1.DeleteBucketResponse{}, nil
}
func (f *fakeS3) GetMutation(_ context.Context, _ *s3v1.GetMutationRequest, _ ...grpc.CallOption) (*s3v1.Mutation, error) {
	state := f.mutationState
	if state == "" {
		state = "SUCCEEDED"
	}
	return &s3v1.Mutation{State: state, Error: "bucket is not empty"}, nil
}

func s3TestCommand(t *testing.T, f *fakeS3) (*Command, *bytes.Buffer, *bytes.Buffer) {
	t.Helper()
	out, errout := new(bytes.Buffer), new(bytes.Buffer)
	c := NewCommand()
	c.Stdout = out
	c.Stderr = errout
	c.Env = func(string) string { return "" }
	c.LoadSDKConfig = func(ctx context.Context, role string) (*motiveiq.Config, error) {
		return motiveiq.LoadDefaultConfig(ctx, motiveiq.WithRoleURN(role))
	}
	c.NewS3FromConfig = func(*motiveiq.Config, string) (S3Client, error) { return f, nil }
	return c, out, errout
}
func s3RunTest(t *testing.T, c *Command, errout *bytes.Buffer, args ...string) {
	t.Helper()
	if code := c.Run(context.Background(), append([]string{"s3"}, args...)); code != 0 {
		t.Fatalf("%v: exit %d: %s", args, code, errout)
	}
}
func writeS3File(t *testing.T, name string, body []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(name), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(name, body, 0600); err != nil {
		t.Fatal(err)
	}
}

func TestS3ListPaginationAndPresentation(t *testing.T) {
	f := newFakeS3()
	f.add("assets", "a.txt", []byte("one"))
	f.add("assets", "dir/b.txt", []byte("two"))
	c, out, errout := s3TestCommand(t, f)
	s3RunTest(t, c, errout, "ls", "s3://assets/", "--page-size", "1", "--summarize")
	if !strings.Contains(out.String(), "         3 a.txt") || !strings.Contains(out.String(), "PRE dir/") || !strings.Contains(out.String(), "Total Objects: 1") {
		t.Fatal(out.String())
	}
	out.Reset()
	s3RunTest(t, c, errout, "ls", "assets/", "--recursive", "--human-readable", "--summarize")
	if !strings.Contains(out.String(), "dir/b.txt") || !strings.Contains(out.String(), "6 Bytes") {
		t.Fatal(out.String())
	}
	out.Reset()
	s3RunTest(t, c, errout, "ls", "assets/dir/b")
	if !strings.Contains(out.String(), "b.txt") {
		t.Fatal("partial prefix truncated the listed filename:", out.String())
	}
	out.Reset()
	s3RunTest(t, c, errout, "ls", "s3://")
	if strings.Index(out.String(), "aaa") > strings.Index(out.String(), "zzz") {
		t.Fatal(out.String())
	}
}

func TestS3MoveRejectsSameObjectAndSymlinkSources(t *testing.T) {
	f := newFakeS3()
	f.add("assets", "key", []byte("original"))
	c, _, _ := s3TestCommand(t, f)
	if c.Run(context.Background(), []string{"s3", "mv", "s3://assets/key", "s3://assets/"}) == 0 {
		t.Fatal("same-object move accepted")
	}
	dir, outside := t.TempDir(), t.TempDir()
	writeS3File(t, filepath.Join(outside, "key"), []byte("original"))
	if err := os.Symlink(outside, filepath.Join(dir, "linked")); err != nil {
		t.Fatal(err)
	}
	if c.Run(context.Background(), []string{"s3", "mv", dir, "s3://assets/", "--recursive"}) == 0 {
		t.Fatal("move through directory symlink accepted")
	}
	if len(f.gets)+len(f.puts)+len(f.deletes) != 0 {
		t.Fatal("unsafe move mutated objects")
	}
}

func TestS3SyncDirectoryMarkersAndExistingCaseCollision(t *testing.T) {
	f := newFakeS3()
	f.add("assets", "prefix/", nil)
	f.add("assets", "prefix/empty/", nil)
	f.add("assets", "prefix/key", []byte("body"))
	c, _, errout := s3TestCommand(t, f)
	dir := t.TempDir()
	s3RunTest(t, c, errout, "sync", "s3://assets/prefix", dir)
	if len(f.gets) != 1 || f.gets[0].Object.Key != "prefix/key" {
		t.Fatal("directory markers treated as files")
	}
	f.gets = nil
	f.add("assets", "prefix/KEY", []byte("body"))
	delete(f.metadata, "assets/prefix/key")
	if c.Run(context.Background(), []string{"s3", "sync", "s3://assets/prefix", dir, "--delete"}) == 0 {
		t.Fatal("existing local case collision accepted")
	}
	if len(f.gets) != 0 {
		t.Fatal("download began before validating existing names")
	}
}

func TestS3DownloadRejectsUnicodeCollisions(t *testing.T) {
	for _, verb := range []string{"cp", "mv", "sync"} {
		for _, tc := range []struct {
			name          string
			first, second string
		}{
			{"equivalent names", "\u00e9.txt", "e\u0301.txt"},
			{"equivalent names and case", "\u00c9.TXT", "e\u0301.txt"},
			{"equivalent parent names", "\u00e9", "e\u0301/child.txt"},
			{"reordered combining marks", "a\u0323\u0301.txt", "a\u0301\u0323.txt"},
		} {
			t.Run(verb+"/"+tc.name, func(t *testing.T) {
				f := newFakeS3()
				f.add("assets", tc.first, []byte("first"))
				f.add("assets", tc.second, []byte("second"))
				c, _, errout := s3TestCommand(t, f)
				dir := t.TempDir()
				args := []string{"s3", verb, "s3://assets/", dir}
				if verb != "sync" {
					args = append(args, "--recursive")
				}
				if c.Run(context.Background(), args) == 0 {
					t.Fatal("Unicode collision accepted")
				}
				if len(f.gets)+len(f.deletes) != 0 {
					t.Fatalf("transfer began before collision validation: %s", errout)
				}
				files, err := os.ReadDir(dir)
				if err != nil || len(files) != 0 {
					t.Fatalf("destination changed: %v, %v", files, err)
				}
			})
		}
	}
}

func TestS3DownloadPreservesDistinctUnicodeNames(t *testing.T) {
	f := newFakeS3()
	keys := []string{"e\u0301.txt", "\u00f1.txt"}
	for _, key := range keys {
		f.add("assets", key, []byte(key))
	}
	c, _, errout := s3TestCommand(t, f)
	dir := t.TempDir()
	s3RunTest(t, c, errout, "sync", "s3://assets/", dir)
	if len(f.gets) != len(keys) {
		t.Fatalf("downloads = %d, want %d", len(f.gets), len(keys))
	}
	for i, key := range keys {
		if f.gets[i].Object.Key != key {
			t.Fatalf("object key changed: %q", f.gets[i].Object.Key)
		}
		got, err := os.ReadFile(filepath.Join(dir, key))
		if err != nil || string(got) != key {
			t.Fatalf("download %q = %q, %v", key, got, err)
		}
	}
}

func TestS3SyncRejectsExistingUnicodeCollisions(t *testing.T) {
	for _, tc := range []struct {
		name          string
		local, remote string
	}{
		{"equivalent names", "e\u0301.txt", "\u00e9.txt"},
		{"equivalent parent names", "e\u0301", "\u00e9/child.txt"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeS3()
			f.add("assets", tc.remote, []byte("replacement"))
			c, _, errout := s3TestCommand(t, f)
			dir := t.TempDir()
			local := filepath.Join(dir, tc.local)
			stale := filepath.Join(dir, "stale.txt")
			writeS3File(t, local, []byte("original"))
			writeS3File(t, stale, []byte("keep"))
			if c.Run(context.Background(), []string{"s3", "sync", "s3://assets/", dir, "--delete"}) == 0 {
				t.Fatal("existing Unicode collision accepted")
			}
			if len(f.gets) != 0 {
				t.Fatalf("download began before collision validation: %s", errout)
			}
			for path, want := range map[string]string{local: "original", stale: "keep"} {
				got, err := os.ReadFile(path)
				if err != nil || string(got) != want {
					t.Fatalf("existing file changed: %s = %q, %v", path, got, err)
				}
			}
		})
	}
}

func TestS3SyncSkippedSymlinksAreNotDeleted(t *testing.T) {
	f := newFakeS3()
	f.add("assets", "linked/key", []byte("keep"))
	f.add("assets", "stale", []byte("delete"))
	dir := t.TempDir()
	if err := os.Symlink("missing", filepath.Join(dir, "linked")); err != nil {
		t.Fatal(err)
	}
	c, _, errout := s3TestCommand(t, f)
	s3RunTest(t, c, errout, "sync", dir, "s3://assets/", "--delete", "--no-follow-symlinks")
	if strings.Join(f.deletes, ",") != "assets/stale" {
		t.Fatal("deleted skipped source:", f.deletes)
	}
	rootLink := filepath.Join(t.TempDir(), "root")
	if err := os.Symlink(dir, rootLink); err != nil {
		t.Fatal(err)
	}
	f.deletes = nil
	s3RunTest(t, c, errout, "sync", rootLink, "s3://assets/", "--delete", "--no-follow-symlinks")
	if len(f.deletes) != 0 {
		t.Fatal("deleted objects below a skipped source root:", f.deletes)
	}
}

func TestS3UploadNeverFinishesChangedOrCancelledInput(t *testing.T) {
	for _, tc := range []struct {
		change string
		size   int
	}{
		{"truncate", 100000}, {"grow", 100000}, {"cancel", 100000},
		{"rewrite", 100000}, {"rewrite empty", 0}, {"rewrite sniffed", 3},
		{"rewrite after data", 100000},
	} {
		t.Run(tc.change, func(t *testing.T) {
			f := newFakeS3()
			name := filepath.Join(t.TempDir(), "input")
			writeS3File(t, name, bytes.Repeat([]byte("x"), tc.size))
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			sent := 0
			f.onSend = func(q *s3v1.PutObjectRequest) {
				if tc.change == "rewrite after data" {
					sent += len(q.GetData())
					if sent != tc.size {
						return
					}
				} else if q.GetHeader() == nil {
					return
				}
				switch tc.change {
				case "truncate":
					if err := os.Truncate(name, 1); err != nil {
						t.Fatal(err)
					}
				case "grow":
					if err := os.Truncate(name, 200000); err != nil {
						t.Fatal(err)
					}
				case "cancel":
					cancel()
				default:
					// A same-length edit must fail before FIN, including after
					// Upload has already sent the final data chunk.
					when := time.Unix(1700000000, 0)
					if err := os.Chtimes(name, when, when); err != nil {
						t.Fatal(err)
					}
				}
			}
			c, _, errout := s3TestCommand(t, f)
			args := []string{"s3", "cp", name, "s3://assets/key"}
			if tc.change != "rewrite sniffed" {
				args = append(args, "--no-guess-mime-type")
			}
			if c.Run(ctx, args) == 0 {
				t.Fatal("invalid upload succeeded")
			}
			if strings.HasPrefix(tc.change, "rewrite") && !strings.Contains(errout.String(), "local source changed during upload") {
				t.Fatalf("lost local source validation: %s", errout)
			}
			if f.commits != 0 {
				t.Fatal("invalid upload emitted FIN")
			}
		})
	}
}

type s3UnreadableInput struct{ t *testing.T }

func (r s3UnreadableInput) Read([]byte) (int, error) {
	r.t.Fatal("dryrun consumed stdin")
	return 0, io.EOF
}

func TestS3DryRunDoesNotReadStdinOrCreateDirectories(t *testing.T) {
	f := newFakeS3()
	f.add("assets", "key", []byte("body"))
	c, out, errout := s3TestCommand(t, f)
	c.Stdin = s3UnreadableInput{t}
	s3RunTest(t, c, errout, "cp", "-", "s3://assets/input", "--dryrun")
	if !strings.Contains(out.String(), "(dryrun) upload:") {
		t.Fatal("missing stdin dryrun output")
	}
	dir := filepath.Join(t.TempDir(), "new")
	s3RunTest(t, c, errout, "sync", "s3://assets/", dir, "--dryrun")
	if _, err := os.Stat(dir); !os.IsNotExist(err) || len(f.gets)+len(f.puts)+len(f.deletes) != 0 {
		t.Fatal("dryrun mutated files or transferred data")
	}
}
func TestS3CopyDirectionsAndStreams(t *testing.T) {
	for _, body := range [][]byte{nil, bytes.Repeat([]byte{0, 1, 2, 255}, 40000)} {
		t.Run(fmt.Sprint(len(body)), func(t *testing.T) {
			f := newFakeS3()
			c, out, errout := s3TestCommand(t, f)
			dir := t.TempDir()
			source := filepath.Join(dir, "file.bin")
			writeS3File(t, source, body)
			s3RunTest(t, c, errout, "cp", source, "s3://assets/path/", "--content-type", "application/custom")
			if !bytes.Equal(f.objects["assets/path/file.bin"], body) || f.metadata["assets/path/file.bin"].ContentType != "application/custom" {
				t.Fatal("upload mismatch")
			}
			target := filepath.Join(dir, "download")
			s3RunTest(t, c, errout, "cp", "s3://assets/path/file.bin", target)
			got, err := os.ReadFile(target)
			if err != nil || !bytes.Equal(got, body) {
				t.Fatalf("download: %v", err)
			}
			original := f.metadata["assets/path/file.bin"]
			original.Metadata = map[string]string{"label": "value"}
			original.CacheControl = "max-age=60"
			original.ContentDisposition = "attachment"
			original.ContentEncoding = "gzip"
			s3RunTest(t, c, errout, "cp", "s3://assets/path/file.bin", "s3://other/new?x=%2F#key")
			if !bytes.Equal(f.objects["other/new?x=%2F#key"], body) {
				t.Fatal("copy changed opaque key or bytes")
			}
			copied := proto.Clone(f.metadata["other/new?x=%2F#key"]).(*s3v1.ObjectMetadata)
			copied.Object, copied.Etag = original.Object, original.Etag
			if !proto.Equal(copied, original) || f.gets[len(f.gets)-1].GetConditions().GetIfMatch() != original.Etag {
				t.Fatal("copy lost metadata or source precondition")
			}
			out.Reset()
			s3RunTest(t, c, errout, "cp", "s3://assets/path/file.bin", "-")
			if !bytes.Equal(out.Bytes(), body) {
				t.Fatal("stdout contains extra bytes")
			}
			c.Stdin = bytes.NewReader(body)
			s3RunTest(t, c, errout, "cp", "-", "s3://assets/stdin")
			if !bytes.Equal(f.objects["assets/stdin"], body) {
				t.Fatal("stdin mismatch")
			}
		})
	}
}
func TestS3FailedDownloadDoesNotPublishOrCompleteCopy(t *testing.T) {
	for _, failure := range []string{"terminal status", "short", "excess", "wrong object"} {
		for _, destination := range []string{"local", "remote"} {
			t.Run(failure+"/"+destination, func(t *testing.T) {
				f := newFakeS3()
				m := f.add("assets", "key", []byte("new"))
				switch failure {
				case "terminal status":
					f.getError = status.Error(codes.DataLoss, "truncated final status")
				case "short":
					m.ContentLength++
				case "excess":
					m.ContentLength--
				case "wrong object":
					m.Object.Key = "wrong"
				}
				c, _, errout := s3TestCommand(t, f)
				dir := t.TempDir()
				target := filepath.Join(dir, "target")
				writeS3File(t, target, []byte("old"))
				if destination == "remote" {
					target = "s3://other/key"
				}
				if c.Run(context.Background(), []string{"s3", "mv", "s3://assets/key", target}) == 0 {
					t.Fatal("failure reported success")
				}
				if f.commits != 0 || len(f.deletes) != 0 {
					t.Fatal("committed or deleted after failed download")
				}
				got, _ := os.ReadFile(filepath.Join(dir, "target"))
				if string(got) != "old" {
					t.Fatal("existing destination was damaged")
				}
				entries, _ := os.ReadDir(dir)
				if len(entries) != 1 {
					t.Fatalf("temporary files remain: %v; %s", entries, errout)
				}
			})
		}
	}
}
func TestS3SyncFiltersDeletionAndDryRun(t *testing.T) {
	f := newFakeS3()
	f.add("assets", "prefix/stale.txt", []byte("stale"))
	f.add("assets", "prefix/keep.jpg", []byte("keep"))
	dir := t.TempDir()
	writeS3File(t, filepath.Join(dir, "new.txt"), []byte("new"))
	writeS3File(t, filepath.Join(dir, "nested/image.jpg"), []byte("image"))
	c, out, errout := s3TestCommand(t, f)
	args := []string{"sync", dir, "s3://assets/prefix", "--exclude", "*", "--include", "*.txt", "--delete"}
	s3RunTest(t, c, errout, append(args, "--dryrun")...)
	if len(f.puts) != 0 || len(f.deletes) != 0 || !strings.Contains(out.String(), "(dryrun) delete:") {
		t.Fatal("dry run mutated state or lost output")
	}
	s3RunTest(t, c, errout, args...)
	if strings.Join(f.puts, ",") != "assets/prefix/new.txt" || strings.Join(f.deletes, ",") != "assets/prefix/stale.txt" {
		t.Fatalf("puts=%v deletes=%v", f.puts, f.deletes)
	}
	if _, ok := f.objects["assets/prefix/keep.jpg"]; !ok {
		t.Fatal("excluded object deleted")
	}
	f.puts = nil
	s3RunTest(t, c, errout, append(args, "--size-only")...)
	if len(f.puts) != 0 {
		t.Fatal("size-only did not converge")
	}
}
func TestS3SyncNeverDeletesAfterListingOrCopyFailure(t *testing.T) {
	for _, failure := range []string{"listing", "copy"} {
		t.Run(failure, func(t *testing.T) {
			f := newFakeS3()
			f.add("source", "a", []byte("a"))
			f.add("source", "b", []byte("b"))
			f.add("target", "stale", []byte("stale"))
			if failure == "listing" {
				f.failPage = 1
				f.listError = errors.New("listing failed")
			} else {
				f.getError = errors.New("read failed")
			}
			c, _, _ := s3TestCommand(t, f)
			if c.Run(context.Background(), []string{"s3", "sync", "s3://source/", "s3://target/", "--delete", "--page-size", "1"}) == 0 {
				t.Fatal("failed sync succeeded")
			}
			if len(f.deletes) != 0 {
				t.Fatal("deleted after failure")
			}
		})
	}
}
func TestS3DownloadRejectsUnsafeMappings(t *testing.T) {
	for _, keys := range [][]string{{"../escape"}, {"/absolute"}, {"a//b"}, {"a/./b"}, {"a\\b"}, {"a", "a/b"}, {"Same", "same"}} {
		t.Run(strings.Join(keys, ","), func(t *testing.T) {
			f := newFakeS3()
			for _, key := range keys {
				f.add("assets", key, []byte("body"))
			}
			c, _, _ := s3TestCommand(t, f)
			dir := t.TempDir()
			if c.Run(context.Background(), []string{"s3", "cp", "s3://assets/", dir, "--recursive"}) == 0 {
				t.Fatal("unsafe mapping accepted")
			}
			if len(f.gets) != 0 {
				t.Fatal("download began before validation")
			}
		})
	}
	f := newFakeS3()
	f.add("assets", "sub/key", []byte("new"))
	c, _, _ := s3TestCommand(t, f)
	dir, outside := t.TempDir(), t.TempDir()
	writeS3File(t, filepath.Join(outside, "key"), []byte("old"))
	if err := os.Symlink(outside, filepath.Join(dir, "sub")); err != nil {
		t.Fatal(err)
	}
	if c.Run(context.Background(), []string{"s3", "sync", "s3://assets/", dir}) == 0 {
		t.Fatal("symlink escape accepted")
	}
	got, _ := os.ReadFile(filepath.Join(outside, "key"))
	if string(got) != "old" {
		t.Fatal("wrote outside destination")
	}
}
func TestS3LocalSyncDeletionAndTimestamps(t *testing.T) {
	f := newFakeS3()
	m := f.add("assets", "key", []byte("new"))
	dir := t.TempDir()
	writeS3File(t, filepath.Join(dir, "stale"), []byte("stale"))
	c, _, errout := s3TestCommand(t, f)
	s3RunTest(t, c, errout, "sync", "s3://assets/", dir, "--delete", "--exact-timestamps")
	if _, err := os.Stat(filepath.Join(dir, "stale")); !os.IsNotExist(err) {
		t.Fatal("stale destination retained")
	}
	st, _ := os.Stat(filepath.Join(dir, "key"))
	if !st.ModTime().Equal(m.LastModified.AsTime()) {
		t.Fatal("download timestamp not preserved")
	}
	f.gets = nil
	s3RunTest(t, c, errout, "sync", "s3://assets/", dir, "--delete", "--exact-timestamps")
	if len(f.gets) != 0 {
		t.Fatal("unchanged object downloaded again")
	}
}
func TestS3MoveAndBucketLifecycle(t *testing.T) {
	f := newFakeS3()
	f.add("assets", "old", []byte("body"))
	c, out, errout := s3TestCommand(t, f)
	s3RunTest(t, c, errout, "mv", "s3://assets/old", "s3://assets/new")
	if len(f.deletes) != 1 || string(f.objects["assets/new"]) != "body" || !strings.Contains(out.String(), "move:") {
		t.Fatal("move failed")
	}
	s3RunTest(t, c, errout, "mb", "s3://new-bucket")
	if f.created.Spec.AccessPolicyJson != `{"version":"1","statements":[]}` || f.created.RequestId == "" {
		t.Fatal("bucket create omitted policy or request id")
	}
	s3RunTest(t, c, errout, "rb", "s3://assets", "--force")
	if f.removed.Bucket.Id != "immutable-id" || f.removed.ExpectedRevision != 7 || len(f.objects) != 0 {
		t.Fatal("delete did not use immutable incarnation/revision")
	}
	f.mutationState = "FAILED"
	if c.Run(context.Background(), []string{"s3", "rb", "s3://assets"}) == 0 {
		t.Fatal("failed deletion reported success")
	}
}
func TestS3GlobAndSyncComparison(t *testing.T) {
	for _, test := range []struct {
		pattern, name string
		want          bool
	}{{"*.txt", "nested/a.txt", true}, {"[!a]*", "boat", true}, {"[!a]*", "apple", false}, {"a?.[ch]", "ab.c", true}, {"[", "[", true}} {
		rx, err := s3Glob(test.pattern)
		if err != nil || rx.MatchString(test.name) != test.want {
			t.Fatalf("%+v: %v", test, err)
		}
	}
	r := s3Run{}
	now := time.Now()
	local := s3Entry{loc: s3Location{local: "file"}, size: 3, modified: now}
	remote := s3Entry{loc: s3Location{bucket: "assets", key: "key"}, size: 3, modified: now.Add(-time.Second)}
	if !r.shouldSync(local, remote) || !r.shouldSync(remote, local) {
		t.Fatal("AWS newer-local comparison changed")
	}
	local.modified = now.Add(-2 * time.Second)
	if r.shouldSync(local, remote) || r.shouldSync(remote, local) {
		t.Fatal("AWS older-local comparison changed")
	}
	r.options.exactTimes = true
	if !r.shouldSync(remote, local) {
		t.Fatal("exact timestamps ignored difference")
	}
}
func TestS3InvalidArgumentsAvoidCredentials(t *testing.T) {
	for _, args := range [][]string{{"cp", "a", "b"}, {"cp", "-", "s3://assets/"}, {"sync", "s3://assets", "-"}, {"mb", "s3://assets/key"}, {"ls", "--endpoint-url", "http://host"}, {"ls", "--page-size", "0"}} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			c, _, _ := s3TestCommand(t, newFakeS3())
			c.LoadSDKConfig = func(context.Context, string) (*motiveiq.Config, error) {
				t.Fatal("credentials loaded for invalid args")
				return nil, nil
			}
			if c.Run(context.Background(), append([]string{"s3"}, args...)) == 0 {
				t.Fatal("invalid args accepted")
			}
		})
	}
}
