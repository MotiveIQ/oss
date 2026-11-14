package publiccli

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	motiveiq "go.motiveiq.dev/platform/iam/sdk"
	sm "go.motiveiq.dev/platform/secretsmanager/api/v1"
)

const secretTestURN = secretURNPrefix + "33333333-3333-4333-8333-333333333333"
const secretTestVersion = "44444444-4444-4444-8444-444444444444"
const secretTestToken = "55555555-5555-4555-8555-555555555555"

type secretFixture struct {
	c              *Command
	conn           *kmsTestConn
	out, errout    bytes.Buffer
	loads          int
	role, endpoint string
	deadline       time.Time
}

func newSecretFixture(invoke func(string, proto.Message) (proto.Message, error)) *secretFixture {
	f := &secretFixture{conn: &kmsTestConn{invoke: invoke}}
	f.c = &Command{Stdout: &f.out, Stderr: &f.errout, Env: func(string) string { return "" }}
	f.c.LoadSDKConfig = func(ctx context.Context, role string) (*motiveiq.Config, error) {
		f.loads++
		f.role = role
		f.deadline, _ = ctx.Deadline()
		return &motiveiq.Config{}, nil
	}
	f.c.NewSecretsManagerFromConfig = func(_ *motiveiq.Config, endpoint string) (SecretsManagerClient, error) {
		f.endpoint = endpoint
		return sm.NewSecretsManagerClient(f.conn), nil
	}
	return f
}

func (f *secretFixture) run(t *testing.T, args ...string) string {
	t.Helper()
	f.out.Reset()
	f.errout.Reset()
	if code := f.c.Run(context.Background(), append([]string{"secretsmanager"}, args...)); code != 0 {
		t.Fatalf("exit=%d: %s", code, &f.errout)
	}
	return f.out.String()
}

func secretTestMetadata() *sm.SecretMetadata {
	return &sm.SecretMetadata{Urn: secretTestURN, Name: "app/database", Description: "Database credentials", KmsKeyUrn: kmsTestKey, Revision: 7, State: sm.SecretState_SECRET_STATE_ACTIVE, CurrentVersionId: secretTestVersion, CreateTime: timestamppb.New(time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC))}
}

func secretTestValue(value string) *sm.SecretValue {
	return &sm.SecretValue{Value: &sm.SecretValue_StringValue{StringValue: value}}
}

func TestSecretsManagerRequests(t *testing.T) {
	meta := secretTestMetadata()
	version := &sm.SecretVersionMetadata{SecretUrn: secretTestURN, VersionId: secretTestVersion}
	urn := &sm.SecretSelector{Selector: &sm.SecretSelector_Urn{Urn: secretTestURN}}
	name := &sm.SecretSelector{Selector: &sm.SecretSelector_Name{Name: "app/database"}}
	cases := []struct {
		verb              string
		args              []string
		request, response proto.Message
		query, want       string
	}{
		{"create-secret", []string{"--name", "app/database", "--kms-key-id", kmsTestID, "--description", "Database credentials", "--secret-string", "secret", "--client-request-token", secretTestToken},
			&sm.CreateSecretRequest{Name: meta.Name, KmsKeyUrn: kmsTestKey, Description: meta.Description, Value: secretTestValue("secret"), RequestId: secretTestToken}, &sm.CreateSecretResponse{Secret: meta, Version: version}, "[URN,Name,VersionId,Revision,ClientRequestToken]", secretTestURN + "\tapp/database\t" + secretTestVersion + "\t7\t" + secretTestToken + "\n"},
		{"put-secret-value", []string{"--secret-id", secretTestURN, "--expected-revision", "6", "--client-request-token", secretTestToken, "--secret-string", "secret"},
			&sm.PutSecretValueRequest{SecretUrn: secretTestURN, Value: secretTestValue("secret"), RequestId: secretTestToken, ExpectedRevision: 6}, &sm.PutSecretValueResponse{Secret: meta, Version: version}, "VersionId", secretTestVersion + "\n"},
		{"get-secret-value", []string{"--secret-id", "app/database"},
			&sm.GetSecretValueRequest{Secret: name}, &sm.GetSecretValueResponse{SecretUrn: secretTestURN, VersionId: secretTestVersion, Value: secretTestValue("  exact\nvalue\t ")}, "SecretString", "  exact\nvalue\t \n"},
		{"get-secret-value", []string{"--secret-id", secretTestURN, "--version-id", secretTestVersion},
			&sm.GetSecretValueRequest{Secret: urn, VersionId: secretTestVersion}, &sm.GetSecretValueResponse{SecretUrn: secretTestURN, VersionId: secretTestVersion, Value: &sm.SecretValue{Value: &sm.SecretValue_BinaryValue{BinaryValue: []byte{0, 255, 10}}}}, "SecretBinary", "AP8K\n"},
		{"describe-secret", []string{"--secret-id", secretTestURN},
			&sm.DescribeSecretRequest{Secret: urn}, meta, "[Name,KmsKeyId,State]", "app/database\t" + kmsTestKey + "\tACTIVE\n"},
		{"update-secret", []string{"--secret-id", secretTestURN, "--expected-revision", "6", "--client-request-token", secretTestToken, "--description", ""},
			&sm.UpdateSecretRequest{SecretUrn: secretTestURN, RequestId: secretTestToken, ExpectedRevision: 6}, meta, "Revision", "7\n"},
		{"delete-secret", []string{"--secret-id", secretTestURN, "--expected-revision", "6", "--client-request-token", secretTestToken},
			&sm.DeleteSecretRequest{SecretUrn: secretTestURN, RequestId: secretTestToken, ExpectedRevision: 6}, meta, "ClientRequestToken", secretTestToken + "\n"},
		{"restore-secret", []string{"--secret-id", secretTestURN, "--expected-revision", "6", "--client-request-token", secretTestToken},
			&sm.RestoreSecretRequest{SecretUrn: secretTestURN, RequestId: secretTestToken, ExpectedRevision: 6}, meta, "URN", secretTestURN + "\n"},
	}
	for _, tt := range cases {
		t.Run(tt.verb+tt.query, func(t *testing.T) {
			f := newSecretFixture(func(method string, q proto.Message) (proto.Message, error) {
				if !strings.HasPrefix(method, "/motiveiq.secretsmanager.v1.SecretsManager/") || !proto.Equal(q, tt.request) {
					t.Fatalf("unexpected method/request: %s %v", method, q)
				}
				return tt.response, nil
			})
			args := append([]string{"--output", "text", tt.verb}, tt.args...)
			args = append(args, "--query", tt.query)
			if got := f.run(t, args...); got != tt.want {
				t.Fatalf("got %q, want %q", got, tt.want)
			}
			if f.loads != 1 || f.role != "" || len(f.conn.calls) != 1 {
				t.Fatalf("unexpected auth/call count: %d %s %d", f.loads, f.role, len(f.conn.calls))
			}
		})
	}
}

func TestSecretsManagerValueFilesAndFormats(t *testing.T) {
	dir := t.TempDir()
	raw := []byte{0, 255, 10, 32}
	text := "  {\"password\":\"synthetic\"}\n"
	for name, data := range map[string][]byte{"raw": raw, "base64": []byte(base64.StdEncoding.EncodeToString(raw) + "\n"), "text": []byte(text)} {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	cases := []struct {
		args  []string
		value *sm.SecretValue
	}{
		{[]string{"--secret-string", "file://" + filepath.Join(dir, "text")}, secretTestValue(text)},
		{[]string{"--secret-string", strings.Repeat("a", 65536)}, secretTestValue(strings.Repeat("a", 65536))},
		{[]string{"--secret-binary", "fileb://" + filepath.Join(dir, "raw")}, &sm.SecretValue{Value: &sm.SecretValue_BinaryValue{BinaryValue: raw}}},
		{[]string{"--secret-binary", "file://" + filepath.Join(dir, "base64")}, &sm.SecretValue{Value: &sm.SecretValue_BinaryValue{BinaryValue: raw}}},
		{[]string{"--secret-binary", "AP8KIA=="}, &sm.SecretValue{Value: &sm.SecretValue_BinaryValue{BinaryValue: raw}}},
		{[]string{"--secret-binary", "file://" + filepath.Join(dir, "raw"), "--cli-binary-format", "raw-in-base64-out"}, &sm.SecretValue{Value: &sm.SecretValue_BinaryValue{BinaryValue: raw}}},
		{[]string{"--secret-binary", "raw", "--cli-binary-format", "raw-in-base64-out"}, &sm.SecretValue{Value: &sm.SecretValue_BinaryValue{BinaryValue: []byte("raw")}}},
	}
	for i, tt := range cases {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			f := newSecretFixture(func(_ string, message proto.Message) (proto.Message, error) {
				q := message.(*sm.CreateSecretRequest)
				if !proto.Equal(q.Value, tt.value) || !secretUUID(q.RequestId) {
					t.Fatal("value changed or missing request ID")
				}
				return &sm.CreateSecretResponse{Secret: secretTestMetadata()}, nil
			})
			output := f.run(t, append([]string{"create-secret", "--name", "app/database", "--kms-key-id", kmsTestKey}, tt.args...)...)
			if !json.Valid([]byte(output)) || strings.Contains(output, "SecretString") || strings.Contains(output, "SecretBinary") || strings.Contains(output, "synthetic") {
				t.Fatalf("unexpected mutation output: %s", output)
			}
		})
	}
}

func TestSecretsManagerRevisionsAndRetryScope(t *testing.T) {
	for _, id := range []string{"app/database", secretTestURN} {
		for _, explicit := range []bool{false, true} {
			t.Run(fmt.Sprint(id, explicit), func(t *testing.T) {
				f := newSecretFixture(func(_ string, message proto.Message) (proto.Message, error) {
					switch q := message.(type) {
					case *sm.DescribeSecretRequest:
						return secretTestMetadata(), nil
					case *sm.PutSecretValueRequest:
						want := int64(7)
						if explicit {
							want = 5
						}
						if q.SecretUrn != secretTestURN || q.ExpectedRevision != want || !secretUUID(q.RequestId) {
							t.Fatalf("unexpected mutation: %v", q)
						}
						return &sm.PutSecretValueResponse{Secret: secretTestMetadata()}, nil
					default:
						t.Fatalf("unexpected request: %T", q)
						return nil, nil
					}
				})
				args := []string{"put-secret-value", "--secret-id", id, "--secret-string", "synthetic"}
				if explicit {
					args = append(args, "--expected-revision", "5")
				}
				f.run(t, args...)
				wantCalls := 2
				if explicit && id == secretTestURN {
					wantCalls = 1
				}
				if len(f.conn.calls) != wantCalls {
					t.Fatalf("calls=%d want=%d", len(f.conn.calls), wantCalls)
				}
			})
		}
	}
	// Exact retries must not re-read a new revision or resolve a recreated name.
	var requests []proto.Message
	f := newSecretFixture(func(_ string, q proto.Message) (proto.Message, error) {
		requests = append(requests, q)
		return &sm.PutSecretValueResponse{Secret: secretTestMetadata()}, nil
	})
	args := []string{"put-secret-value", "--secret-id", secretTestURN, "--secret-string", "synthetic", "--expected-revision", "6", "--client-request-token", secretTestToken}
	f.run(t, args...)
	f.run(t, args...)
	if len(requests) != 2 || !proto.Equal(requests[0], requests[1]) {
		t.Fatal("exact retry changed the request")
	}
}

func TestSecretsManagerMutationFailurePreservesRetryInputs(t *testing.T) {
	for _, code := range []codes.Code{codes.Aborted, codes.Unavailable, codes.PermissionDenied} {
		f := newSecretFixture(func(_ string, q proto.Message) (proto.Message, error) {
			if _, ok := q.(*sm.DescribeSecretRequest); ok {
				return secretTestMetadata(), nil
			}
			return nil, status.Error(code, "synthetic failure")
		})
		if f.c.Run(context.Background(), []string{"secretsmanager", "put-secret-value", "--secret-id", "app/database", "--secret-string", "SENSITIVE_SENTINEL"}) == 0 {
			t.Fatal("failure succeeded")
		}
		if len(f.conn.calls) != 2 || f.out.Len() != 0 {
			t.Fatal("retried mutation or emitted success output")
		}
		id := f.conn.calls[1].request.(*sm.PutSecretValueRequest).RequestId
		for _, text := range []string{id, secretTestURN, "expected-revision 7", "same inputs"} {
			if !strings.Contains(f.errout.String(), text) {
				t.Fatalf("missing retry input %s: %s", text, &f.errout)
			}
		}
		if strings.Contains(f.errout.String(), "SENSITIVE_SENTINEL") {
			t.Fatal("secret leaked in error")
		}
	}
}

func TestSecretsManagerValidationBeforeCredentials(t *testing.T) {
	create := []string{"create-secret", "--name", "app/database", "--kms-key-id", kmsTestKey}
	write := []string{"put-secret-value", "--secret-id", secretTestURN, "--secret-string", "valid"}
	cases := [][]string{
		append(append([]string{}, create...), "--secret-string", ""),
		append(append([]string{}, create...), "--secret-string", strings.Repeat("a", 65537)),
		append(append([]string{}, create...), "--secret-string", string([]byte{255})),
		append(append([]string{}, create...), "--secret-string", "fileb://anything"),
		append(append([]string{}, create...), "--secret-binary", "SENSITIVE_SENTINEL"),
		append(append([]string{}, create...), "--secret-binary", ""),
		append(append([]string{}, create...), "--secret-string", "one", "--secret-binary", "dHdv"),
		create,
		{"create-secret", "--name", "a//b", "--kms-key-id", kmsTestKey, "--secret-string", "valid"},
		{"create-secret", "--name", "app/database", "--kms-key-id", "alias/key", "--secret-string", "valid"},
		append(append([]string{}, write...), "--expected-revision", "0"),
		append(append([]string{}, write...), "--expected-revision", "-1"),
		append(append([]string{}, write...), "--client-request-token", secretTestToken),
		{"put-secret-value", "--secret-id", "app/database", "--secret-string", "valid", "--expected-revision", "7", "--client-request-token", secretTestToken},
		append(append([]string{}, write...), "--expected-revision", "7", "--client-request-token", "not-uuid"),
		{"get-secret-value", "--secret-id", ""},
		{"get-secret-value", "--secret-id", secretTestURN, "--version-id", ""},
		{"get-secret-value", "--secret-id", secretTestURN, "--version-stage", "AWSCURRENT"},
		{"update-secret", "--secret-id", secretTestURN},
		{"delete-secret", "--secret-id", secretTestURN, "--force-delete-without-recovery"},
		{"list-secrets", "--page-size", "101"},
		{"list-secrets", "--page-size", "0"},
		{"list-secrets", "--max-items", "0"},
		{"list-secrets", "--max-items", "-1"},
		{"list-secrets", "--max-items", "1", "--no-paginate"},
		{"list-secrets", "--query", "["},
		{"list-secrets", "--output", "csv"},
		{"list-secrets", "--endpoint-url", "http://localhost"},
		{"list-secrets", "--timeout", "0"},
		{"list-secrets", "--cli-binary-format", "raw"},
		{"list-secrets", "--name-prefix", strings.Repeat("a", 256)},
		{"list-secrets", "--starting-token", strings.Repeat("a", 2049)},
	}
	for i, args := range cases {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			f := newSecretFixture(nil)
			if f.c.Run(context.Background(), append([]string{"secretsmanager"}, args...)) == 0 {
				t.Fatal("invalid arguments succeeded")
			}
			if f.loads != 0 || len(f.conn.calls) != 0 || f.out.Len() != 0 {
				t.Fatal("invalid arguments loaded credentials or emitted output")
			}
			if strings.Contains(f.errout.String(), "SENSITIVE_SENTINEL") {
				t.Fatal("invalid binary input leaked")
			}
		})
	}
	for _, data := range [][]byte{nil, {255}, bytes.Repeat([]byte("x"), 65537)} {
		path := filepath.Join(t.TempDir(), "invalid.txt")
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
		f := newSecretFixture(nil)
		args := append(append([]string{"secretsmanager"}, create...), "--secret-string", "file://"+path)
		if f.c.Run(context.Background(), args) == 0 || f.loads != 0 {
			t.Fatal("invalid file accepted")
		}
	}
}

func TestSecretsManagerPagination(t *testing.T) {
	for _, verb := range []string{"list-secrets", "list-secret-version-ids"} {
		for _, mode := range []string{"all", "max", "capped", "one", "resume"} {
			t.Run(verb+mode, func(t *testing.T) {
				var sizes []uint32
				var tokens []string
				f := newSecretFixture(func(_ string, q proto.Message) (proto.Message, error) {
					var size uint32
					var token string
					switch q := q.(type) {
					case *sm.ListSecretsRequest:
						size, token = q.PageSize, q.PageToken
						if q.NamePrefix != "app/" {
							t.Fatal("filter lost")
						}
					case *sm.ListSecretVersionsRequest:
						size, token = q.PageSize, q.PageToken
						if q.Secret.GetUrn() != secretTestURN {
							t.Fatal("selector lost")
						}
					default:
						t.Fatalf("unexpected request %T", q)
					}
					sizes = append(sizes, size)
					tokens = append(tokens, token)
					next := "next"
					if token == "next" {
						next = ""
					}
					if verb == "list-secrets" {
						return &sm.ListSecretsResponse{Secrets: []*sm.SecretMetadata{secretTestMetadata()}, NextPageToken: next}, nil
					}
					return &sm.ListSecretVersionsResponse{Versions: []*sm.SecretVersionMetadata{{SecretUrn: secretTestURN, VersionId: secretTestVersion, Current: true}}, NextPageToken: next}, nil
				})
				args := []string{verb, "--page-size", "2"}
				if verb == "list-secrets" {
					args = append(args, "--name-prefix", "app/")
				} else {
					args = append(args, "--secret-id", secretTestURN)
				}
				wantSizes := []uint32{2, 2}
				wantTokens := []string{"", "next"}
				wantCount := 2
				switch mode {
				case "capped":
					args = append(args, "--max-items", "1")
					wantSizes = []uint32{1}
					wantTokens = []string{""}
					wantCount = 1
				case "max":
					args = append(args, "--max-items", "2")
					wantSizes = []uint32{2, 1}
				case "one":
					args = append(args, "--no-paginate")
					wantSizes = []uint32{2}
					wantTokens = []string{""}
					wantCount = 1
				case "resume":
					args = append(args, "--starting-token", "next")
					wantSizes = []uint32{2}
					wantTokens = []string{"next"}
					wantCount = 1
				}
				output := f.run(t, args...)
				var result map[string]any
				if err := json.Unmarshal([]byte(output), &result); err != nil {
					t.Fatal(err)
				}
				field := "SecretList"
				if verb != "list-secrets" {
					field = "Versions"
				}
				if len(result[field].([]any)) != wantCount || !reflect.DeepEqual(sizes, wantSizes) || !reflect.DeepEqual(tokens, wantTokens) {
					t.Fatalf("result %s, sizes %v, tokens %v", output, sizes, tokens)
				}
				if (result["NextToken"] != nil) != (mode == "one" || mode == "capped") {
					t.Fatalf("wrong continuation: %s", output)
				}
			})
		}
	}
}

func TestSecretsManagerPaginationFailureAndAggregateQuery(t *testing.T) {
	for _, failure := range []bool{false, true} {
		f := newSecretFixture(func(_ string, q proto.Message) (proto.Message, error) {
			if q.(*sm.ListSecretsRequest).PageToken != "" && failure {
				return nil, status.Error(codes.PermissionDenied, "no longer authorized")
			}
			return &sm.ListSecretsResponse{Secrets: []*sm.SecretMetadata{secretTestMetadata()}, NextPageToken: "repeated"}, nil
		})
		if f.c.Run(context.Background(), []string{"secretsmanager", "list-secrets"}) == 0 || len(f.conn.calls) != 2 || f.out.Len() != 0 {
			t.Fatal("pagination error failed to stop or emitted partial success")
		}
	}
	f := newSecretFixture(func(_ string, q proto.Message) (proto.Message, error) {
		next := ""
		if q.(*sm.ListSecretsRequest).PageToken == "" {
			next = "second"
		}
		return &sm.ListSecretsResponse{Secrets: []*sm.SecretMetadata{secretTestMetadata()}, NextPageToken: next}, nil
	})
	if output := f.run(t, "list-secrets", "--query", "length(SecretList)", "--output", "text"); output != "2\n" {
		t.Fatalf("query not applied to aggregate: %q", output)
	}
}

func TestSecretsManagerOutput(t *testing.T) {
	meta := secretTestMetadata()
	meta.State = sm.SecretState_SECRET_STATE_PENDING_DELETION
	meta.DeletionTime = timestamppb.New(time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC))
	meta.Description = strings.Repeat("long", 100)
	f := newSecretFixture(func(_ string, q proto.Message) (proto.Message, error) {
		switch q.(type) {
		case *sm.ListSecretsRequest:
			return &sm.ListSecretsResponse{Secrets: []*sm.SecretMetadata{meta}, NextPageToken: "copyable-token"}, nil
		default:
			return meta, nil
		}
	})
	table := f.run(t, "list-secrets", "--no-paginate", "--output", "table")
	for _, want := range []string{"Name", "State", "Revision", "URN", "PENDING_DELETION", "Pagination", "copyable-token", secretTestURN} {
		if !strings.Contains(table, want) {
			t.Fatalf("missing %s in table %s", want, table)
		}
	}
	if strings.Contains(table, "long") {
		t.Fatal("list table expanded description")
	}
	table = f.run(t, "describe-secret", "--secret-id", secretTestURN, "--output", "table")
	if !strings.Contains(table, "2026-10-21T12:00:00Z") || !strings.Contains(table, "…") || strings.Contains(table, meta.Description) {
		t.Fatalf("bad deletion/description table: %s", table)
	}
	for _, format := range []string{"json", "yaml", "text"} {
		output := f.run(t, "describe-secret", "--secret-id", secretTestURN, "--query", "Description", "--output", format)
		if !strings.Contains(output, meta.Description) {
			t.Fatalf("%s truncated value", format)
		}
	}
	f = newSecretFixture(func(_ string, _ proto.Message) (proto.Message, error) {
		return &sm.GetSecretValueResponse{SecretUrn: secretTestURN, Value: secretTestValue("line\n\x1b[31m")}, nil
	})
	table = f.run(t, "get-secret-value", "--secret-id", secretTestURN, "--output", "table")
	if strings.Contains(table, "\x1b") || !strings.Contains(table, `line\n\x1b[31m`) {
		t.Fatalf("unsafe/unreadable table: %q", table)
	}
	f = newSecretFixture(func(_ string, _ proto.Message) (proto.Message, error) { return &sm.ListSecretsResponse{}, nil })
	if output := f.run(t, "list-secrets"); !strings.Contains(output, `"SecretList": []`) {
		t.Fatalf("empty result not array: %s", output)
	}
}

func TestSecretsManagerConfigurationAndErrors(t *testing.T) {
	f := newSecretFixture(func(_ string, _ proto.Message) (proto.Message, error) { return &sm.ListSecretsResponse{}, nil })
	f.c.Env = func(name string) string {
		switch name {
		case SecretsManagerEndpointEnv:
			return "https://localhost:8443"
		case defaultOutputEnv:
			return "yaml"
		}
		return ""
	}
	output := f.run(t, "list-secrets", "--role", "urn:motiveiq:iam:role/test", "--timeout", "2s")
	if f.endpoint != "dns:///localhost:8443" || f.role != "urn:motiveiq:iam:role/test" || time.Until(f.deadline) > 2*time.Second || f.deadline.IsZero() || !strings.Contains(output, "SecretList: []") {
		t.Fatalf("config not used: %s %s %v %s", f.endpoint, f.role, f.deadline, output)
	}
	f.run(t, "list-secrets", "--endpoint-url", "https://localhost:9443")
	if f.endpoint != "dns:///localhost:9443" {
		t.Fatalf("override ignored: %s", f.endpoint)
	}
	f = newSecretFixture(nil)
	f.c.LoadSDKConfig = func(context.Context, string) (*motiveiq.Config, error) {
		return nil, errors.New("credentials unavailable")
	}
	if f.c.Run(context.Background(), []string{"secretsmanager", "list-secrets"}) == 0 || !strings.Contains(f.errout.String(), "credentials unavailable") || len(f.conn.calls) != 0 {
		t.Fatal("credential failure ignored")
	}
}

func TestSecretsManagerOutputFailureReportsCommittedMutation(t *testing.T) {
	f := newSecretFixture(func(_ string, _ proto.Message) (proto.Message, error) {
		return &sm.CreateSecretResponse{Secret: secretTestMetadata()}, nil
	})
	// This query compiles, but length(number) fails after the RPC succeeds.
	args := []string{"secretsmanager", "create-secret", "--name", "app/database", "--kms-key-id", kmsTestKey, "--secret-string", "synthetic", "--query", "length(Revision)"}
	if f.c.Run(context.Background(), args) == 0 || len(f.conn.calls) != 1 || f.out.Len() != 0 {
		t.Fatal("output error was ignored or mutation repeated")
	}
	for _, want := range []string{"succeeded", "output failed", secretTestURN, f.conn.calls[0].request.(*sm.CreateSecretRequest).RequestId} {
		if !strings.Contains(f.errout.String(), want) {
			t.Fatalf("missing committed result %s: %s", want, &f.errout)
		}
	}
}

func TestSecretsManagerInvalidMetadataPreventsMutation(t *testing.T) {
	for _, meta := range []*sm.SecretMetadata{
		{Urn: secretTestURN, Revision: 0},
		{Urn: "app/database", Revision: 7},
		{Urn: secretURNPrefix + secretTestToken, Revision: 7},
	} {
		f := newSecretFixture(func(_ string, _ proto.Message) (proto.Message, error) { return meta, nil })
		if f.c.Run(context.Background(), []string{"secretsmanager", "delete-secret", "--secret-id", secretTestURN}) == 0 || len(f.conn.calls) != 1 {
			t.Fatal("invalid metadata allowed a mutation")
		}
	}
}
