package publiccli

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"math"
	"mime"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	s3v1 "go.motiveiq.dev/platform/s3/api/v1"
)

type s3Task struct {
	source      s3Entry
	destination s3Location
}

func (r *s3Run) transfer(ctx context.Context, verb string, locations []s3Location) error {
	r.rejectSourceSymlinks = verb == "mv"
	src := locations[0]
	var dst s3Location
	if len(locations) > 1 {
		dst = locations[1]
	}
	recursive := r.options.recursive || verb == "sync"
	if src.remote() && dst.remote() && src.bucket == dst.bucket {
		if src.key == dst.key || (recursive && (strings.HasPrefix(src.prefix().key, dst.prefix().key) || strings.HasPrefix(dst.prefix().key, src.prefix().key))) {
			return fmt.Errorf("source and destination S3 paths overlap")
		}
	}
	var tasks, deletions []s3Task
	var localRoot string
	if recursive {
		entries, err := r.inventory(ctx, src, false, true)
		if err != nil {
			return err
		}
		if verb != "rm" && !dst.remote() {
			if err := s3CheckLocalTargets(entries); err != nil {
				return err
			}
			localRoot = dst.local
		}
		existing := map[string]s3Entry{}
		if verb == "sync" {
			targets, err := r.inventory(ctx, dst, true, false)
			if err != nil {
				return err
			}
			for _, e := range targets {
				existing[e.relative] = e
			}
			if !dst.remote() {
				combined := make(map[string]s3Entry, len(existing)+len(entries))
				for name, entry := range existing {
					combined[name] = entry
				}
				for _, entry := range entries {
					combined[entry.relative] = entry
				}
				if err := s3CheckLocalTargets(s3InventoryFromMap(combined)); err != nil {
					return err
				}
			}
		}
		sourceNames := map[string]bool{}
		for _, e := range entries {
			sourceNames[e.relative] = true
			if verb == "rm" {
				deletions = append(deletions, s3Task{source: e})
				continue
			}
			if !dst.remote() && e.directoryMarker() {
				continue
			}
			if old, ok := existing[e.relative]; verb == "sync" && ok && !r.shouldSync(e, old) {
				continue
			}
			tasks = append(tasks, s3Task{source: e, destination: dst.child(e.relative)})
		}
		if verb == "sync" && r.options.delete {
			targets := s3InventoryFromMap(existing)
			for _, e := range targets {
				if !sourceNames[e.relative] && !r.sourceIgnored(e.relative) {
					deletions = append(deletions, s3Task{source: e})
				}
			}
		}
	} else {
		if src.remote() && src.key == "" {
			return fmt.Errorf("an object key is required without --recursive")
		}
		if verb == "rm" {
			if r.options.included(path.Base(src.key)) {
				deletions = append(deletions, s3Task{source: s3Entry{loc: src}})
			}
		} else {
			source, err := r.singleSource(ctx, src)
			if err != nil {
				return err
			}
			if !r.options.included(source.relative) {
				return nil
			}
			if dst.remote() {
				if dst.key == "" || strings.HasSuffix(dst.key, "/") {
					dst = dst.child(source.relative)
				}
			} else if !dst.stream() {
				info, err := os.Stat(dst.local)
				if err != nil && !os.IsNotExist(err) {
					return err
				}
				if (info != nil && info.IsDir()) || strings.HasSuffix(dst.local, string(filepath.Separator)) {
					if err := s3LocalRelative(source.relative); err != nil {
						return err
					}
					dst = dst.child(source.relative)
				}
				localRoot = filepath.Dir(dst.local)
			}
			tasks = append(tasks, s3Task{source: source, destination: dst})
		}
	}
	for _, task := range tasks {
		if task.source.loc.remote() && task.destination.remote() && task.source.loc.bucket == task.destination.bucket && task.source.loc.key == task.destination.key {
			return fmt.Errorf("source and destination refer to the same object")
		}
	}
	// The complete listing/plan must succeed before any writes or deletes.
	var root *os.Root
	if localRoot != "" && !r.options.dryrun && (len(tasks) > 0 || len(deletions) > 0) {
		if err := os.MkdirAll(localRoot, 0755); err != nil {
			return err
		}
		var err error
		root, err = os.OpenRoot(localRoot)
		if err != nil {
			return err
		}
		defer root.Close()
		for _, task := range tasks {
			relative, err := filepath.Rel(localRoot, task.destination.local)
			if err != nil {
				return err
			}
			if err := s3CheckSymlinks(root, relative); err != nil {
				return err
			}
		}
	}
	for _, task := range tasks {
		if err := ctx.Err(); err != nil {
			return err
		}
		action := "copy"
		if !task.source.loc.remote() {
			action = "upload"
		} else if !task.destination.remote() {
			action = "download"
		}
		if verb == "mv" {
			action = "move"
		}
		if !r.options.dryrun {
			if err := r.copy(ctx, task, root, localRoot); err != nil {
				return fmt.Errorf("%s failed: %s to %s: %w", action, s3Display(task.source.loc.String()), s3Display(task.destination.String()), err)
			}
			if verb == "mv" {
				if err := r.remove(ctx, task.source); err != nil {
					return fmt.Errorf("copied, but could not remove source %s: %w", s3Display(task.source.loc.String()), err)
				}
			}
		}
		if r.options.dryrun || (!task.source.loc.stream() && !task.destination.stream()) {
			if err := r.report(action, task.source.loc.String(), task.destination.String()); err != nil {
				return err
			}
		}
	}
	// A failed listing, source read, upload, or local publish never reaches here.
	for _, task := range deletions {
		if err := ctx.Err(); err != nil {
			return err
		}
		if !r.options.dryrun {
			var err error
			if task.source.loc.remote() {
				err = r.remove(ctx, task.source)
			} else {
				var relative string
				relative, err = filepath.Rel(localRoot, task.source.loc.local)
				if err == nil {
					err = s3RemoveLocal(root, relative, task.source.info)
				}
			}
			if err != nil {
				return fmt.Errorf("delete failed: %s: %w", s3Display(task.source.loc.String()), err)
			}
		}
		if err := r.report("delete", task.source.loc.String(), ""); err != nil {
			return err
		}
	}
	return nil
}

func s3InventoryFromMap(entries map[string]s3Entry) []s3Entry {
	result := make([]s3Entry, 0, len(entries))
	for _, e := range entries {
		result = append(result, e)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].relative < result[j].relative })
	return result
}

func (r *s3Run) shouldSync(src, dst s3Entry) bool {
	if src.size != dst.size {
		return true
	}
	if r.options.sizeOnly {
		return false
	}
	if r.options.exactTimes {
		return !src.modified.Equal(dst.modified)
	}
	// AWS CLI's download comparison differs from upload/copy: a newer local
	// destination is downloaded again. Downloads restore the remote timestamp.
	if src.loc.remote() && !dst.loc.remote() {
		return dst.modified.After(src.modified)
	}
	return src.modified.After(dst.modified)
}

func (r *s3Run) singleSource(ctx context.Context, loc s3Location) (s3Entry, error) {
	entry := s3Entry{loc: loc}
	if loc.remote() {
		result, err := r.client.HeadObject(ctx, &s3v1.HeadObjectRequest{Object: loc.object()})
		if err != nil {
			return entry, err
		}
		m := result.GetMetadata()
		if m == nil {
			return entry, fmt.Errorf("missing object metadata")
		}
		entry.metadata = m
		entry.size = m.ContentLength
		entry.relative = path.Base(loc.key)
		if m.LastModified != nil {
			entry.modified = m.LastModified.AsTime()
		}
	} else {
		entry.relative = filepath.Base(loc.local)
		if loc.stream() {
			return entry, nil
		}
		info, err := os.Stat(loc.local)
		if err != nil {
			return entry, err
		}
		if !info.Mode().IsRegular() {
			return entry, fmt.Errorf("%s is not a regular file; directories require --recursive", loc.local)
		}
		if r.options.noFollow || r.rejectSourceSymlinks {
			link, err := os.Lstat(loc.local)
			if err != nil {
				return entry, err
			}
			if link.Mode()&os.ModeSymlink != 0 {
				return entry, fmt.Errorf("source is a symbolic link (mv and --no-follow-symlinks do not follow links)")
			}
		}
		entry.info = info
		entry.size = uint64(info.Size())
		entry.modified = info.ModTime()
	}
	return entry, nil
}

func (r *s3Run) remove(ctx context.Context, e s3Entry) error {
	if e.loc.remote() {
		var conditions *s3v1.ObjectConditions
		if e.metadata != nil {
			if e.metadata.Etag == "" {
				return fmt.Errorf("missing ETag for conditional deletion")
			}
			conditions = &s3v1.ObjectConditions{IfMatch: e.metadata.Etag}
		}
		_, err := r.client.DeleteObject(ctx, &s3v1.DeleteObjectRequest{Object: e.loc.object(), Conditions: conditions})
		return err
	}
	// Local sync deletion never follows a symlink in the destination tree.
	root, err := os.OpenRoot(filepath.Dir(e.loc.local))
	if err != nil {
		return err
	}
	defer root.Close()
	return s3RemoveLocal(root, filepath.Base(e.loc.local), e.info)
}
func s3SameLocal(a, b os.FileInfo) bool {
	return a != nil && b != nil && os.SameFile(a, b) && a.Size() == b.Size() && a.ModTime().Equal(b.ModTime())
}

func (r *s3Run) copy(ctx context.Context, task s3Task, root *os.Root, localRoot string) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	source := task.source
	var reader io.Reader
	var file *os.File
	var metadata *s3v1.ObjectMetadata
	if source.loc.remote() {
		conditions := &s3v1.ObjectConditions{}
		if source.metadata != nil {
			conditions.IfMatch = source.metadata.Etag
		}
		download, err := r.client.Download(ctx, &s3v1.GetObjectRequest{Object: source.loc.object(), Conditions: conditions})
		if err != nil {
			return err
		}
		defer download.Body.Close()
		metadata = download.Metadata
		if metadata.ContentLength > math.MaxInt64 {
			return fmt.Errorf("object is too large")
		}
		if source.metadata != nil && (source.size != metadata.ContentLength || source.metadata.Etag != metadata.Etag) {
			return fmt.Errorf("remote source changed since it was listed")
		}
		source.size = metadata.ContentLength
		if metadata.LastModified != nil {
			source.modified = metadata.LastModified.AsTime()
		}
		reader = download.Body
	} else {
		var err error
		if source.loc.stream() {
			if input, ok := r.command.Stdin.(*os.File); ok {
				stop := context.AfterFunc(ctx, func() { _ = input.Close() })
				defer stop()
			}
			file, err = os.CreateTemp("", "iq-s3-stdin-*")
			if err != nil {
				return err
			}
			defer os.Remove(file.Name())
			defer file.Close()
			if _, err = io.CopyBuffer(file, &s3ContextReader{ctx: ctx, reader: r.command.Stdin}, make([]byte, 64*1024)); err != nil {
				return err
			}
			if _, err = file.Seek(0, io.SeekStart); err != nil {
				return err
			}
			source.info, err = file.Stat()
			if err != nil {
				return err
			}
			source.size = uint64(source.info.Size())
		} else {
			file, err = os.Open(source.loc.local)
			if err != nil {
				return err
			}
			defer file.Close()
			current, err := file.Stat()
			if err != nil {
				return err
			}
			if !s3SameLocal(source.info, current) {
				return fmt.Errorf("local source changed since it was listed")
			}
		}
		reader = &s3LocalSourceReader{file: file, expected: source.info}
	}
	reader = &s3ContextReader{ctx: ctx, reader: reader}
	if task.destination.remote() {
		header := &s3v1.PutObjectHeader{Bucket: task.destination.bucket, Key: task.destination.key, ContentLength: &source.size}
		if metadata != nil {
			header.ContentType = metadata.ContentType
			header.ContentEncoding = metadata.ContentEncoding
			header.ContentDisposition = metadata.ContentDisposition
			header.CacheControl = metadata.CacheControl
			header.Metadata = metadata.Metadata
		} else {
			header.ContentType = "application/octet-stream"
			if !r.options.noGuess {
				if guessed := mime.TypeByExtension(filepath.Ext(source.relative)); guessed != "" {
					header.ContentType = guessed
				} else {
					var prefix [512]byte
					n, err := io.ReadFull(reader, prefix[:])
					if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
						return err
					}
					header.ContentType = http.DetectContentType(prefix[:n])
					reader = io.MultiReader(strings.NewReader(string(prefix[:n])), reader)
				}
			}
		}
		if r.options.contentType != "" {
			header.ContentType = r.options.contentType
		}
		if r.options.cacheControl != "" {
			header.CacheControl = r.options.cacheControl
		}
		if r.options.contentDisposition != "" {
			header.ContentDisposition = r.options.contentDisposition
		}
		if r.options.contentEncoding != "" {
			header.ContentEncoding = r.options.contentEncoding
		}
		_, err := r.client.Upload(ctx, header, reader)
		return err
	}
	if task.destination.stream() {
		_, err := io.CopyBuffer(r.command.Stdout, reader, make([]byte, 64*1024))
		return err
	}
	relative, err := filepath.Rel(localRoot, task.destination.local)
	if err != nil {
		return err
	}
	return s3PublishLocal(ctx, root, relative, reader, source.modified)
}

type s3ContextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r *s3ContextReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.reader.Read(p)
}

// Upload requires EOF before signing FIN. Check the local file at that boundary
// so a changed source cannot be committed, even if its length stayed the same.
type s3LocalSourceReader struct {
	file     *os.File
	expected os.FileInfo
}

func (r *s3LocalSourceReader) Read(p []byte) (int, error) {
	n, err := r.file.Read(p)
	if err == io.EOF {
		current, statErr := r.file.Stat()
		if statErr != nil {
			return n, statErr
		}
		if !s3SameLocal(r.expected, current) {
			return n, fmt.Errorf("local source changed during upload")
		}
	}
	return n, err
}

func s3CheckSymlinks(root *os.Root, relative string) error {
	if err := s3LocalRelative(filepath.ToSlash(relative)); err != nil {
		return err
	}
	current := ""
	for _, part := range strings.Split(relative, string(filepath.Separator)) {
		current = filepath.Join(current, part)
		info, err := root.Lstat(current)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("download destination contains a symbolic link: %s", current)
		}
	}
	return nil
}
func s3PublishLocal(ctx context.Context, root *os.Root, relative string, reader io.Reader, modified time.Time) error {
	if root == nil {
		return fmt.Errorf("local destination root is not open")
	}
	if err := s3CheckSymlinks(root, relative); err != nil {
		return err
	}
	if err := root.MkdirAll(filepath.Dir(relative), 0755); err != nil {
		return err
	}
	random := make([]byte, 16)
	if _, err := rand.Read(random); err != nil {
		return err
	}
	temporary := filepath.Join(filepath.Dir(relative), ".iq-s3-"+hex.EncodeToString(random))
	file, err := root.OpenFile(temporary, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer root.Remove(temporary)
	defer file.Close()
	if _, err := io.CopyBuffer(file, reader, make([]byte, 64*1024)); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if !modified.IsZero() {
		if err := root.Chtimes(temporary, modified, modified); err != nil {
			return err
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := s3CheckSymlinks(root, relative); err != nil {
		return err
	}
	return root.Rename(temporary, relative)
}

func s3RemoveLocal(root *os.Root, relative string, expected os.FileInfo) error {
	if root == nil {
		return fmt.Errorf("local destination root is not open")
	}
	if err := s3CheckSymlinks(root, relative); err != nil {
		return err
	}
	info, err := root.Lstat(relative)
	if err != nil {
		return err
	}
	if !s3SameLocal(expected, info) {
		return fmt.Errorf("local file changed since it was listed")
	}
	return root.Remove(relative)
}

func (r *s3Run) sourceIgnored(relative string) bool {
	for _, prefix := range r.ignoredSources {
		if prefix == "" || relative == prefix || strings.HasPrefix(relative, prefix+"/") {
			return true
		}
	}
	return false
}
