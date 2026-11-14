package publiccli

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"
	s3v1 "go.motiveiq.dev/platform/s3/api/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const S3EndpointEnv = "IQ_S3_ENDPOINT"

type s3Options struct {
	role, endpoint string
	pageSize       int32
	timeout        time.Duration
	filters        []s3Filter

	recursive, dryrun, quiet, onlyErrors                            bool
	human, summarize, delete, sizeOnly, exactTimes, force, noFollow bool
	noGuess                                                         bool

	contentType, cacheControl, contentDisposition, contentEncoding string
	policyFile                                                     string
}

func (c *Command) s3Command() *cobra.Command {
	o := &s3Options{}
	command := &cobra.Command{Use: "s3", Short: "Manage MotiveIQ buckets and objects with S3-style commands.", Long: `Manage MotiveIQ S3 using your configured identity source and IAM role.
Paths are local paths or s3://bucket/key. No AWS credentials are used.
Run iq s3 COMMAND --help for supported options.`, RunE: func(cmd *cobra.Command, _ []string) error { _ = cmd.Help(); return errUsage }}
	command.PersistentFlags().StringVar(&o.role, "role", "", "MotiveIQ IAM role URN to assume.")
	command.PersistentFlags().StringVar(&o.endpoint, "endpoint-url", c.Env(S3EndpointEnv), "HTTPS S3 service endpoint (also IQ_S3_ENDPOINT).")
	command.PersistentFlags().Int32Var(&o.pageSize, "page-size", 1000, "Number of entries per API page (1-1000); all pages are read.")
	command.PersistentFlags().DurationVar(&o.timeout, "timeout", time.Hour, "Deadline for the entire command, including bucket readiness.")
	for _, verb := range []string{"ls", "cp", "mv", "rm", "sync", "mb", "rb"} {
		use, short, args := verb+" <S3Uri>", "", cobra.ExactArgs(1)
		switch verb {
		case "ls":
			use, short, args = "ls [S3Uri]", "List buckets, objects, or common prefixes.", cobra.MaximumNArgs(1)
		case "cp", "mv", "sync":
			use, short, args = verb+" <source> <destination>", "Transfer local files and S3 objects.", cobra.ExactArgs(2)
		case "rm":
			short = "Delete objects."
		case "mb":
			short = "Create a bucket and wait for it to become ready."
		case "rb":
			short = "Remove a bucket and wait for deletion."
		}
		child := &cobra.Command{Use: use, Short: short, Args: args, RunE: func(cmd *cobra.Command, args []string) error { return c.runS3(cmd.Context(), verb, args, *o) }}
		if verb == "cp" || verb == "mv" || verb == "sync" {
			child.ValidArgsFunction = func(_ *cobra.Command, _ []string, word string) ([]string, cobra.ShellCompDirective) {
				if strings.HasPrefix(word, "s3://") {
					return nil, cobra.ShellCompDirectiveNoFileComp
				}
				return nil, cobra.ShellCompDirectiveDefault
			}
		}
		f := child.Flags()
		if verb == "ls" {
			f.BoolVar(&o.recursive, "recursive", false, "List every object below the prefix.")
			f.BoolVar(&o.human, "human-readable", false, "Display sizes in binary units.")
			f.BoolVar(&o.summarize, "summarize", false, "Display total object count and size.")
		} else {
			f.BoolVar(&o.dryrun, "dryrun", false, "Print planned operations without changing files or objects.")
			f.BoolVar(&o.quiet, "quiet", false, "Suppress operation output.")
			f.BoolVar(&o.onlyErrors, "only-show-errors", false, "Display only errors.")
		}
		if verb == "cp" || verb == "mv" || verb == "rm" {
			f.BoolVar(&o.recursive, "recursive", false, "Operate on all files or objects below the source.")
		}
		if verb == "cp" || verb == "mv" || verb == "sync" || verb == "rm" {
			f.Var(&s3FilterFlag{filters: &o.filters}, "exclude", "Exclude matching paths; later include/exclude options take precedence.")
			f.Var(&s3FilterFlag{filters: &o.filters, include: true}, "include", "Re-include matching paths excluded by an earlier filter.")
		}
		if verb == "cp" || verb == "mv" || verb == "sync" {
			f.Bool("no-progress", false, "Disable progress output (transfers always use one completion line).")
			f.BoolVar(&o.noFollow, "no-follow-symlinks", false, "Skip symbolic links in local upload sources.")
			f.BoolVar(&o.noGuess, "no-guess-mime-type", false, "Use application/octet-stream instead of inferring content type.")
			f.StringVar(&o.contentType, "content-type", "", "Set destination Content-Type.")
			f.StringVar(&o.cacheControl, "cache-control", "", "Set destination Cache-Control.")
			f.StringVar(&o.contentDisposition, "content-disposition", "", "Set destination Content-Disposition.")
			f.StringVar(&o.contentEncoding, "content-encoding", "", "Set destination Content-Encoding.")
		}
		if verb == "sync" {
			f.BoolVar(&o.delete, "delete", false, "Delete destination files absent from source, after successful transfers.")
			f.BoolVar(&o.sizeOnly, "size-only", false, "Compare sizes only.")
			f.BoolVar(&o.exactTimes, "exact-timestamps", false, "For downloads, compare equal-size files using exact timestamps.")
			child.MarkFlagsMutuallyExclusive("size-only", "exact-timestamps")
		}
		if verb == "mb" {
			f.StringVar(&o.policyFile, "policy-file", "", "MotiveIQ bucket policy JSON file; default is an empty, closed policy.")
		}
		if verb == "rb" {
			f.BoolVar(&o.force, "force", false, "Delete all objects before removing the bucket.")
		}
		command.AddCommand(child)
	}
	return command
}

func s3Endpoint(value string) (string, error) {
	if value == "" {
		return "", nil
	}
	u, err := url.Parse(value)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return "", fmt.Errorf("--endpoint-url must be an HTTPS origin without credentials, path, query, or fragment")
	}
	if u.Port() == "" {
		return "dns:///" + u.Host + ":443", nil
	}
	return "dns:///" + u.Host, nil
}

func (c *Command) runS3(ctx context.Context, verb string, args []string, o s3Options) error {
	if o.pageSize < 1 || o.pageSize > 1000 {
		return fmt.Errorf("--page-size must be between 1 and 1000")
	}
	if o.timeout <= 0 {
		return fmt.Errorf("--timeout must be positive")
	}
	endpoint, err := s3Endpoint(o.endpoint)
	if err != nil {
		return err
	}
	// Parse before credential discovery so usage mistakes do not trigger login/network work.
	if verb == "ls" && len(args) == 1 && args[0] == "s3://" {
		args = nil
	}
	locations := make([]s3Location, len(args))
	for i, arg := range args {
		if verb == "ls" && !strings.HasPrefix(arg, "s3://") {
			arg = "s3://" + arg
		}
		locations[i], err = parseS3Location(arg)
		if err != nil {
			return err
		}
	}
	if verb == "ls" && len(locations) == 1 && locations[0].bucket == "" {
		locations = nil
	}
	if verb == "mb" || verb == "rb" {
		if !locations[0].remote() || locations[0].key != "" {
			return fmt.Errorf("%s requires s3://bucket with no object key", verb)
		}
	}
	if verb == "rm" && !locations[0].remote() {
		return fmt.Errorf("rm requires an s3:// path")
	}
	if verb == "cp" || verb == "mv" || verb == "sync" {
		src, dst := locations[0], locations[1]
		if !src.remote() && !dst.remote() {
			return fmt.Errorf("at least one path must be s3://bucket/key")
		}
		if src.stream() || dst.stream() {
			if verb != "cp" || o.recursive {
				return fmt.Errorf("standard streams are supported only for non-recursive cp")
			}
			if src.stream() && (dst.key == "" || strings.HasSuffix(dst.key, "/")) {
				return fmt.Errorf("stdin uploads require an exact destination key")
			}
		}
		if o.exactTimes && (!src.remote() || dst.remote()) {
			return fmt.Errorf("--exact-timestamps is supported only for S3-to-local sync")
		}
	}
	ctx, cancel := context.WithTimeout(ctx, o.timeout)
	defer cancel()
	cfg, err := c.LoadSDKConfig(ctx, o.role)
	if err != nil {
		return err
	}
	defer cfg.Close()
	client, err := c.NewS3FromConfig(cfg, endpoint)
	if err != nil {
		return err
	}
	run := &s3Run{command: c, client: client, options: o}
	switch verb {
	case "ls":
		return run.list(ctx, locations)
	case "mb", "rb":
		return run.bucket(ctx, verb, locations[0])
	default:
		return run.transfer(ctx, verb, locations)
	}
}

type s3Run struct {
	command              *Command
	client               S3Client
	options              s3Options
	ignoredSources       []string
	rejectSourceSymlinks bool
}

func (r *s3Run) report(operation, src, dst string) error {
	if r.options.quiet || r.options.onlyErrors {
		return nil
	}
	prefix := ""
	if r.options.dryrun {
		prefix = "(dryrun) "
	}
	line := prefix + operation + ": " + s3Display(src)
	if dst != "" {
		line += " to " + s3Display(dst)
	}
	_, err := fmt.Fprintln(r.command.Stdout, line)
	return err
}

func s3Display(s string) string {
	return strings.Map(func(c rune) rune {
		if c < 32 || c == 127 {
			return '\uFFFD'
		}
		return c
	}, s)
}
func s3Time(t *timestamppb.Timestamp) string {
	if t == nil {
		return "0000-00-00 00:00:00"
	}
	return t.AsTime().Local().Format("2006-01-02 15:04:05")
}
func s3Size(n uint64, human bool) string {
	if !human {
		return fmt.Sprint(n)
	}
	if n < 1024 {
		return fmt.Sprintf("%d Bytes", n)
	}
	size, unit := float64(n), 0
	units := []string{"Bytes", "KiB", "MiB", "GiB", "TiB", "PiB", "EiB"}
	for size >= 1024 && unit < len(units)-1 {
		size /= 1024
		unit++
	}
	return fmt.Sprintf("%.1f %s", size, units[unit])
}

func (r *s3Run) list(ctx context.Context, locations []s3Location) error {
	if len(locations) == 0 {
		token := ""
		seen := map[string]bool{}
		var buckets []*s3v1.Bucket
		for {
			page, err := r.client.ListBuckets(ctx, &s3v1.ListBucketsRequest{PageSize: r.options.pageSize, PageToken: token})
			if err != nil {
				return err
			}
			buckets = append(buckets, page.GetBuckets()...)
			token = page.GetNextPageToken()
			if token == "" {
				break
			}
			if seen[token] {
				return fmt.Errorf("repeated bucket pagination token")
			}
			seen[token] = true
		}
		sort.Slice(buckets, func(i, j int) bool { return buckets[i].Name < buckets[j].Name })
		for _, b := range buckets {
			if _, err := fmt.Fprintf(r.command.Stdout, "%s %s\n", s3Time(b.CreateTime), s3Display(b.Name)); err != nil {
				return err
			}
		}
		return nil
	}
	loc := locations[0]
	displayPrefix := loc.key[:strings.LastIndex(loc.key, "/")+1]
	delimiter := "/"
	if r.options.recursive {
		delimiter = ""
	}
	var total, count uint64
	err := r.objects(ctx, loc, delimiter, func(page *s3v1.ListObjectsResponse) error {
		for _, prefix := range page.CommonPrefixes {
			if _, err := fmt.Fprintf(r.command.Stdout, "                           PRE %s\n", s3Display(strings.TrimPrefix(prefix, displayPrefix))); err != nil {
				return err
			}
		}
		for _, object := range page.Objects {
			name := object.GetObject().GetKey()
			if !r.options.recursive {
				name = strings.TrimPrefix(name, displayPrefix)
			}
			if _, err := fmt.Fprintf(r.command.Stdout, "%s %10s %s\n", s3Time(object.LastModified), s3Size(object.ContentLength, r.options.human), s3Display(name)); err != nil {
				return err
			}
			total += object.ContentLength
			count++
		}
		return nil
	})
	if err != nil {
		return err
	}
	if r.options.summarize {
		_, err = fmt.Fprintf(r.command.Stdout, "\nTotal Objects: %d\n   Total Size: %s\n", count, s3Size(total, r.options.human))
	}
	return err
}

func (r *s3Run) bucket(ctx context.Context, verb string, loc s3Location) error {
	operation := "make_bucket"
	if verb == "rb" {
		operation = "remove_bucket"
	}
	requestID := make([]byte, 16)
	if _, err := rand.Read(requestID); err != nil {
		return err
	}
	id := hex.EncodeToString(requestID)
	var ref *s3v1.BucketRef
	if verb == "mb" {
		policy := []byte(`{"version":"1","statements":[]}`)
		if r.options.policyFile != "" {
			var err error
			policy, err = os.ReadFile(r.options.policyFile)
			if err != nil {
				return err
			}
		}
		if r.options.dryrun {
			return r.report(operation, loc.bucket, "")
		}
		result, err := r.client.CreateBucket(ctx, &s3v1.CreateBucketRequest{Name: loc.bucket, Spec: &s3v1.BucketSpec{AccessPolicyJson: string(policy)}, RequestId: id})
		if err != nil {
			return err
		}
		ref = &s3v1.BucketRef{Name: loc.bucket, Id: result.GetBucket().GetId()}
	} else {
		result, err := r.client.GetBucket(ctx, &s3v1.GetBucketRequest{Bucket: &s3v1.BucketRef{Name: loc.bucket}})
		if err != nil {
			return err
		}
		ref = &s3v1.BucketRef{Name: loc.bucket, Id: result.GetBucket().GetId()}
		if ref.Id == "" || result.GetBucket().GetRevision() == 0 {
			return fmt.Errorf("control plane returned no bucket ID or revision")
		}
		if r.options.force {
			saved := r.options.recursive
			r.options.recursive = true
			err = r.transfer(ctx, "rm", []s3Location{loc})
			r.options.recursive = saved
			if err != nil {
				return err
			}
		}
		if r.options.dryrun {
			return r.report(operation, loc.bucket, "")
		}
		_, err = r.client.DeleteBucket(ctx, &s3v1.DeleteBucketRequest{Bucket: ref, ExpectedRevision: result.GetBucket().GetRevision(), RequestId: id})
		if err != nil {
			return err
		}
	}
	if ref.Id == "" {
		return fmt.Errorf("control plane returned no bucket ID")
	}
	for {
		if verb == "mb" {
			result, err := r.client.GetBucket(ctx, &s3v1.GetBucketRequest{Bucket: ref})
			if err != nil {
				return err
			}
			if result.GetBucket().GetReady() {
				break
			}
		} else {
			result, err := r.client.GetMutation(ctx, &s3v1.GetMutationRequest{BucketName: loc.bucket, RequestId: id})
			if err != nil {
				return err
			}
			switch result.GetState() {
			case "SUCCEEDED":
				return r.report(operation, loc.bucket, "")
			case "FAILED", "SUPERSEDED":
				return fmt.Errorf("bucket deletion %s: %s", strings.ToLower(result.GetState()), result.GetError())
			}
		}
		timer := time.NewTimer(time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
			return fmt.Errorf("waiting for bucket %s (request %s): %w", loc.bucket, id, ctx.Err())
		case <-timer.C:
		}
	}
	return r.report(operation, loc.bucket, "")
}
