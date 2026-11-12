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

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	motiveiq "go.motiveiq.dev/platform/iam/sdk"
	kmsv1 "go.motiveiq.dev/platform/kms/api/v1"
)

const kmsTestID = "11111111-1111-4111-8111-111111111111"
const kmsTestKey = kmsKeyPrefix + kmsTestID
const kmsTestRequestID = "22222222-2222-4222-8222-222222222222"

type kmsTestCall struct {
	method  string
	request proto.Message
}
type kmsTestConn struct {
	calls  []kmsTestCall
	invoke func(string, proto.Message) (proto.Message, error)
}

func (c *kmsTestConn) Invoke(_ context.Context, method string, request, response any, _ ...grpc.CallOption) error {
	q := proto.Clone(request.(proto.Message))
	c.calls = append(c.calls, kmsTestCall{method, q})
	result, err := c.invoke(method, q)
	if err != nil {
		return err
	}
	proto.Merge(response.(proto.Message), result)
	return nil
}
func (*kmsTestConn) NewStream(context.Context, *grpc.StreamDesc, string, ...grpc.CallOption) (grpc.ClientStream, error) {
	return nil, errors.New("unexpected stream")
}

type kmsFixture struct {
	c              *Command
	conn           *kmsTestConn
	out, errout    *bytes.Buffer
	loads          int
	endpoint, role string
}

func newKMSFixture(t *testing.T, invoke func(string, proto.Message) (proto.Message, error)) *kmsFixture {
	t.Helper()
	f := &kmsFixture{conn: &kmsTestConn{invoke: invoke}, out: new(bytes.Buffer), errout: new(bytes.Buffer)}
	f.c = &Command{Stdout: f.out, Stderr: f.errout, Env: func(string) string { return "" }}
	f.c.LoadSDKConfig = func(_ context.Context, role string) (*motiveiq.Config, error) {
		f.loads++
		f.role = role
		return &motiveiq.Config{}, nil
	}
	f.c.NewKMSFromConfig = func(_ *motiveiq.Config, endpoint string) (KMSClient, error) {
		f.endpoint = endpoint
		return &kmsClient{DataPlaneClient: kmsv1.NewDataPlaneClient(f.conn), ControlPlaneClient: kmsv1.NewControlPlaneClient(f.conn)}, nil
	}
	return f
}
func (f *kmsFixture) run(t *testing.T, args ...string) string {
	t.Helper()
	f.out.Reset()
	f.errout.Reset()
	if code := f.c.Run(context.Background(), append([]string{"kms"}, args...)); code != 0 {
		t.Fatalf("exit=%d: %s", code, f.errout.String())
	}
	return f.out.String()
}

func TestKMSDataRequestsAndAWSOutput(t *testing.T) {
	ref := &kmsv1.KeyMaterialRef{KeyUrn: kmsTestKey, MaterialVersion: "version"}
	cases := []struct {
		name              string
		args              []string
		request, response proto.Message
		query, want       string
	}{
		{"encrypt", []string{"encrypt", "--key-id", "alias/payments", "--plaintext", "aGVsbG8=", "--encryption-context", `tenant=acme,note="a,b"`},
			&kmsv1.EncryptRequest{Key: kmsAliasPrefix + "payments", Plaintext: []byte("hello"), EncryptionContext: map[string]string{"tenant": "acme", "note": "a,b"}},
			&kmsv1.EncryptResponse{Key: ref, CiphertextBlob: []byte("cipher")}, "CiphertextBlob", "Y2lwaGVy\n"},
		{"decrypt", []string{"decrypt", "--key-id", kmsTestID, "--ciphertext-blob", "Y2lwaGVy", "--encryption-context", `{"tenant":"acme"}`},
			&kmsv1.DecryptRequest{KeyUrn: kmsTestKey, CiphertextBlob: []byte("cipher"), EncryptionContext: map[string]string{"tenant": "acme"}},
			&kmsv1.DecryptResponse{Key: ref, Plaintext: []byte("hello"), Purpose: kmsv1.CiphertextPurpose_CIPHERTEXT_PURPOSE_SMALL_VALUE}, "Plaintext", "aGVsbG8=\n"},
		{"re-encrypt", []string{"re-encrypt", "--source-key-id", kmsTestKey, "--destination-key-id", "alias/new", "--ciphertext-blob", "Y2lwaGVy", "--source-encryption-context", "tenant=old", "--destination-encryption-context", "tenant=new"},
			&kmsv1.ReEncryptRequest{SourceKeyUrn: kmsTestKey, DestinationKey: kmsAliasPrefix + "new", CiphertextBlob: []byte("cipher"), SourceEncryptionContext: map[string]string{"tenant": "old"}, DestinationEncryptionContext: map[string]string{"tenant": "new"}},
			&kmsv1.ReEncryptResponse{Source: ref, Destination: ref, CiphertextBlob: []byte("new")}, "[SourceKeyId,KeyId,CiphertextBlob]", kmsTestKey + "\t" + kmsTestKey + "\tbmV3\n"},
		{"generate-data-key", []string{"generate-data-key", "--key-id", kmsTestKey, "--key-spec", "AES_256"},
			&kmsv1.GenerateDataKeyRequest{Key: kmsTestKey, Size: &kmsv1.GenerateDataKeyRequest_KeySpec{KeySpec: kmsv1.DataKeySpec_DATA_KEY_SPEC_AES_256}},
			&kmsv1.GenerateDataKeyResponse{Key: ref, Plaintext: []byte("secret"), CiphertextBlob: []byte("cipher")}, "Plaintext", "c2VjcmV0\n"},
		{"generate-data-key-without-plaintext", []string{"generate-data-key-without-plaintext", "--key-id", kmsTestID, "--number-of-bytes", "64"},
			&kmsv1.GenerateDataKeyRequest{Key: kmsTestKey, Size: &kmsv1.GenerateDataKeyRequest_NumberOfBytes{NumberOfBytes: 64}},
			&kmsv1.GenerateDataKeyWithoutPlaintextResponse{Key: ref, CiphertextBlob: []byte("cipher")}, "contains(keys(@), 'Plaintext')", "False\n"},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			f := newKMSFixture(t, func(_ string, q proto.Message) (proto.Message, error) {
				if !proto.Equal(q, tt.request) {
					t.Fatalf("request=%v want=%v", q, tt.request)
				}
				return tt.response, nil
			})
			args := append(tt.args, "--query", tt.query, "--output", "text")
			if got := f.run(t, args...); got != tt.want {
				t.Fatalf("got %q want %q", got, tt.want)
			}
			if f.loads != 1 || len(f.conn.calls) != 1 || f.role != IAMHumanRoleURN {
				t.Fatal("unexpected authentication or request count")
			}
		})
	}
}

func TestKMSControlRequestMapping(t *testing.T) {
	mutation := func() *kmsv1.KeyMutationRequest {
		return &kmsv1.KeyMutationRequest{KeyUrn: kmsTestKey, RequestId: kmsTestRequestID, ExpectedRevision: 4}
	}
	key := &kmsv1.KeyRequest{KeyUrn: kmsTestKey}
	cases := []struct {
		verb, method      string
		args              []string
		request, response proto.Message
	}{
		{"create-key", "CreateKey", []string{"--description", "example", "--policy", `{"version":"1","statements":[]}`}, &kmsv1.CreateKeyRequest{RequestId: kmsTestRequestID, Description: "example", PolicyDocument: `{"version":"1","statements":[]}`, RotationPolicy: &kmsv1.RotationPolicy{PeriodDays: 90}}, nil},
		{"describe-key", "DescribeKey", nil, key, &kmsv1.KeyMetadata{KeyUrn: kmsTestKey}},
		{"update-key-description", "UpdateKeyDescription", []string{"--description", "new"}, &kmsv1.UpdateKeyDescriptionRequest{KeyUrn: kmsTestKey, RequestId: kmsTestRequestID, ExpectedRevision: 4, Description: "new"}, nil},
		{"enable-key", "EnableKey", nil, mutation(), nil}, {"disable-key", "DisableKey", nil, mutation(), nil}, {"rotate-key-on-demand", "RotateKey", nil, mutation(), nil}, {"cancel-key-deletion", "CancelKeyDeletion", nil, mutation(), nil},
		{"enable-key-rotation", "PutRotationPolicy", []string{"--rotation-period-in-days", "30"}, &kmsv1.PutRotationPolicyRequest{KeyUrn: kmsTestKey, RequestId: kmsTestRequestID, ExpectedRevision: 4, RotationPolicy: &kmsv1.RotationPolicy{PeriodDays: 30}}, nil},
		{"get-key-rotation-status", "GetRotationPolicy", nil, key, &kmsv1.GetRotationPolicyResponse{RotationPolicy: &kmsv1.RotationPolicy{PeriodDays: 90}}},
		{"schedule-key-deletion", "ScheduleKeyDeletion", nil, &kmsv1.ScheduleKeyDeletionRequest{KeyUrn: kmsTestKey, RequestId: kmsTestRequestID, ExpectedRevision: 4, PendingWindowDays: 30}, nil},
		{"put-key-policy", "PutKeyPolicy", []string{"--policy", `{"version":"1","statements":[]}`}, &kmsv1.PutKeyPolicyRequest{KeyUrn: kmsTestKey, RequestId: kmsTestRequestID, ExpectedRevision: 4, PolicyDocument: `{"version":"1","statements":[]}`}, nil},
		{"get-key-policy", "GetKeyPolicy", nil, key, &kmsv1.GetKeyPolicyResponse{DesiredDocument: `{"version":"1","statements":[]}`}},
		{"create-alias", "CreateAlias", []string{"--alias-name", "alias/example", "--target-key-id", kmsTestID}, &kmsv1.CreateAliasRequest{AliasUrn: kmsAliasPrefix + "example", KeyUrn: kmsTestKey, RequestId: kmsTestRequestID}, nil},
		{"update-alias", "UpdateAlias", []string{"--alias-name", "alias/example", "--target-key-id", kmsTestID}, &kmsv1.UpdateAliasRequest{AliasUrn: kmsAliasPrefix + "example", KeyUrn: kmsTestKey, RequestId: kmsTestRequestID, ExpectedRevision: 4}, nil},
		{"delete-alias", "DeleteAlias", []string{"--alias-name", kmsAliasPrefix + "example"}, &kmsv1.DeleteAliasRequest{AliasUrn: kmsAliasPrefix + "example", RequestId: kmsTestRequestID, ExpectedRevision: 4}, nil},
		{"get-alias", "GetAlias", []string{"--alias-name", "alias/example"}, &kmsv1.GetAliasRequest{AliasUrn: kmsAliasPrefix + "example"}, &kmsv1.AliasMetadata{AliasUrn: kmsAliasPrefix + "example", KeyUrn: kmsTestKey, Revision: 4}},
		{"get-operation", "GetOperation", []string{"--request-id", kmsTestRequestID}, &kmsv1.GetOperationRequest{RequestId: kmsTestRequestID}, &kmsv1.Operation{RequestId: kmsTestRequestID, State: kmsv1.OperationState_OPERATION_STATE_SUCCEEDED}},
	}
	for _, tt := range cases {
		t.Run(tt.verb, func(t *testing.T) {
			args := append([]string{tt.verb}, tt.args...)
			if !strings.HasSuffix(tt.verb, "-alias") && tt.verb != "create-key" && tt.verb != "get-operation" {
				args = append(args, "--key-id", kmsTestID)
			}
			if kmsMutation(tt.verb) {
				args = append(args, "--request-id", kmsTestRequestID)
			}
			if kmsNeedsRevision(tt.verb) {
				args = append(args, "--expected-revision", "4")
			}
			response := tt.response
			if response == nil {
				response = &kmsv1.Operation{RequestId: kmsTestRequestID, OperationType: tt.method, AcceptedRevision: 5, ResultKeyUrn: kmsTestKey, State: kmsv1.OperationState_OPERATION_STATE_SUCCEEDED}
			}
			f := newKMSFixture(t, func(method string, q proto.Message) (proto.Message, error) {
				if !strings.HasSuffix(method, "/"+tt.method) || !proto.Equal(q, tt.request) {
					t.Fatalf("%s: %v want %s: %v", method, q, tt.method, tt.request)
				}
				return response, nil
			})
			output := f.run(t, args...)
			if !json.Valid([]byte(output)) || len(f.conn.calls) != 1 {
				t.Fatalf("invalid output or extra requests: %s", output)
			}
		})
	}
}

func TestKMSAutomaticRevisionsAndExplicitReplay(t *testing.T) {
	for _, alias := range []bool{false, true} {
		t.Run(fmt.Sprint(alias), func(t *testing.T) {
			f := newKMSFixture(t, func(_ string, q proto.Message) (proto.Message, error) {
				switch r := q.(type) {
				case *kmsv1.KeyRequest:
					return &kmsv1.KeyMetadata{KeyUrn: r.KeyUrn, Revision: 17}, nil
				case *kmsv1.GetAliasRequest:
					return &kmsv1.AliasMetadata{AliasUrn: r.AliasUrn, KeyUrn: kmsTestKey, Revision: 17}, nil
				case *kmsv1.KeyMutationRequest:
					if r.ExpectedRevision != 17 || kmsRequestID(r.RequestId) != nil {
						t.Fatalf("bad mutation: %v", r)
					}
				case *kmsv1.DeleteAliasRequest:
					if r.ExpectedRevision != 17 || kmsRequestID(r.RequestId) != nil {
						t.Fatalf("bad mutation: %v", r)
					}
				default:
					t.Fatalf("unexpected request %T", r)
				}
				return &kmsv1.Operation{State: kmsv1.OperationState_OPERATION_STATE_SUCCEEDED}, nil
			})
			args := []string{"disable-key", "--key-id", kmsTestID}
			if alias {
				args = []string{"delete-alias", "--alias-name", "alias/example"}
			}
			f.run(t, args...)
			if len(f.conn.calls) != 2 {
				t.Fatal("expected metadata read then mutation")
			}
			// Explicit retries do not read mutable metadata, including deleted aliases.
			f.conn.calls = nil
			f.run(t, append(args, "--request-id", kmsTestRequestID, "--expected-revision", "17")...)
			if len(f.conn.calls) != 1 {
				t.Fatal("retry performed a metadata read")
			}
		})
	}
}

func TestKMSValidationBeforeCredentials(t *testing.T) {
	cases := [][]string{
		{"encrypt", "--key-id", kmsTestID},
		{"encrypt", "--key-id", kmsTestID, "--plaintext", "private!not-base64"},
		{"encrypt", "--key-id", kmsTestID, "--plaintext", "aA==", "--query", "["},
		{"encrypt", "--key-id", kmsTestID, "--plaintext", "aA==", "--output", "xml"},
		{"encrypt", "--key-id", kmsTestID, "--plaintext", "aA==", "--endpoint-url", "http://localhost"},
		{"encrypt", "--key-id", kmsTestID, "--plaintext", "aA==", "--cli-binary-format", "bad"},
		{"encrypt", "--key-id", kmsTestID, "--plaintext", "aA==", "--encryption-algorithm", ""},
		{"encrypt", "--key-id", kmsTestID, "--plaintext", "aA==", "--encryption-context", `{"a":null}`},
		{"encrypt", "--key-id", kmsTestID, "--plaintext", "aA==", "--encryption-context", `{"a":"one","a":"two"}`},
		{"decrypt", "--key-id", "alias/example", "--ciphertext-blob", "aA=="},
		{"re-encrypt", "--source-key-id", "alias/example", "--destination-key-id", kmsTestID, "--ciphertext-blob", "aA=="},
		{"generate-data-key", "--key-id", kmsTestID},
		{"generate-data-key", "--key-id", kmsTestID, "--key-spec", "AES_128"},
		{"generate-data-key", "--key-id", kmsTestID, "--key-spec", "AES_256", "--number-of-bytes", "32"},
		{"generate-data-key", "--key-id", kmsTestID, "--number-of-bytes", "0"},
		{"generate-data-key", "--key-id", kmsTestID, "--number-of-bytes", "1025"},
		{"create-key", "--key-spec", "RSA_2048"}, {"create-key", "--key-usage", "SIGN_VERIFY"},
		{"create-key", "--policy", "not json"}, {"create-key", "--rotation-period-in-days", "366"},
		{"get-key-policy", "--key-id", kmsTestID, "--policy-name", "other"},
		{"schedule-key-deletion", "--key-id", kmsTestID, "--pending-window-in-days", "6"},
		{"disable-key", "--key-id", kmsTestID, "--expected-revision", "0"},
		{"disable-key", "--key-id", kmsTestID, "--request-id", kmsTestRequestID},
		{"disable-key", "--key-id", kmsTestID, "--expected-revision", "1", "--request-id", "bad"},
		{"create-alias", "--alias-name", "alias/a//b", "--target-key-id", kmsTestID},
		{"describe-key", "--key-id", ""}, {"list-keys", "--page-size", "201"}, {"list-keys", "--max-items", "0"},
		{"list-keys", "--max-items", "1", "--no-paginate"}, {"list-keys", "--timeout", "0s"},
		{"wait", "operation-succeeded", "--request-id", "bad"},
	}
	for i, args := range cases {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			f := newKMSFixture(t, func(string, proto.Message) (proto.Message, error) { t.Fatal("RPC before validation"); return nil, nil })
			if code := f.c.Run(context.Background(), append([]string{"kms"}, args...)); code == 0 {
				t.Fatal("invalid input accepted")
			}
			if f.loads != 0 || f.out.Len() != 0 || strings.Contains(f.errout.String(), "private!not-base64") {
				t.Fatalf("side effects or secret in output: %s", f.errout)
			}
		})
	}
}

func TestKMSBinaryInputsAndContexts(t *testing.T) {
	dir := t.TempDir()
	raw := []byte{0, 255, 1, 2, 10}
	rawPath, encodedPath := filepath.Join(dir, "raw"), filepath.Join(dir, "base64")
	if err := os.WriteFile(rawPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(encodedPath, []byte(base64.StdEncoding.EncodeToString(raw)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ input, format string }{
		{"fileb://" + rawPath, "base64"}, {"fileb://" + rawPath, "raw-in-base64-out"},
		{"file://" + encodedPath, "base64"}, {"file://" + rawPath, "raw-in-base64-out"},
		{base64.StdEncoding.EncodeToString(raw), "base64"}, {string(raw), "raw-in-base64-out"},
	} {
		got, err := kmsBlob(tc.input, "plaintext", tc.format, 4096)
		if err != nil || !bytes.Equal(got, raw) {
			t.Fatalf("binary input %s: %v", tc.format, err)
		}
	}
	if _, err := kmsBlob(strings.Repeat("x", 4097), "plaintext", "raw-in-base64-out", 4096); err == nil {
		t.Fatal("oversized plaintext accepted")
	}
	if _, err := kmsBlob("fileb://"+rawPath, "plaintext", "base64", 4); err == nil {
		t.Fatal("oversized binary file accepted")
	}
	cases := []struct {
		input string
		want  map[string]string
	}{
		{`tenant=acme,note="a,b=c",space=' a ',escaped=a\,b,empty=`, map[string]string{"tenant": "acme", "note": "a,b=c", "space": " a ", "escaped": "a,b", "empty": ""}},
		{`{"tenant":"acme","note":"☃"}`, map[string]string{"tenant": "acme", "note": "☃"}},
	}
	for _, tc := range cases {
		got, err := kmsContext(tc.input, "encryption-context")
		if err != nil || !reflect.DeepEqual(got, tc.want) {
			t.Fatalf("context=%v err=%v", got, err)
		}
	}
	for _, value := range []string{`a=x,a=y`, `a="unclosed`, `a=b,`, `a=b\`, `{"a":1}`, `{"a":{}}`, `{"a":"b"} trailing`, "a=" + strings.Repeat("x", 2048)} {
		if _, err := kmsContext(value, "encryption-context"); err == nil {
			t.Fatalf("invalid context accepted: %q", value)
		}
	}
	policy := filepath.Join(dir, "policy.json")
	if err := os.WriteFile(policy, []byte(`{"version":"1","statements":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	f := newKMSFixture(t, func(_ string, q proto.Message) (proto.Message, error) {
		if q.(*kmsv1.CreateKeyRequest).PolicyDocument != `{"version":"1","statements":[]}` {
			t.Fatal("policy file was not loaded")
		}
		return &kmsv1.Operation{OperationType: "CreateKey", ResultKeyUrn: kmsTestKey, State: kmsv1.OperationState_OPERATION_STATE_PENDING}, nil
	})
	if got := f.run(t, "create-key", "--policy", "file://"+policy, "--query", "KeyMetadata.KeyId", "--output", "text"); got != kmsTestKey+"\n" {
		t.Fatal(got)
	}
}

func TestKMSPaginationAppliesQueryAfterAggregation(t *testing.T) {
	for _, verb := range []string{"list-keys", "list-aliases"} {
		t.Run(verb, func(t *testing.T) {
			f := newKMSFixture(t, func(_ string, q proto.Message) (proto.Message, error) {
				var size uint32
				var token string
				switch r := q.(type) {
				case *kmsv1.ListKeysRequest:
					size, token = r.PageSize, r.PageToken
				case *kmsv1.ListAliasesRequest:
					size, token = r.PageSize, r.PageToken
				}
				start := 0
				if token == "second" {
					start = 2
				} else if token == "third" {
					start = 3
				}
				if start == 0 && size != 2 || start == 2 && size != 1 {
					t.Fatalf("page size=%d start=%d", size, start)
				}
				next := ""
				if start == 0 {
					next = "second"
				}
				if start == 2 {
					next = "third"
				}
				if verb == "list-keys" {
					page := &kmsv1.ListKeysResponse{NextPageToken: next}
					for i := 0; i < int(size); i++ {
						page.Keys = append(page.Keys, &kmsv1.KeyMetadata{KeyUrn: fmt.Sprint(start + i)})
					}
					return page, nil
				}
				page := &kmsv1.ListAliasesResponse{NextPageToken: next}
				for i := 0; i < int(size); i++ {
					page.Aliases = append(page.Aliases, &kmsv1.AliasMetadata{AliasUrn: kmsAliasPrefix + fmt.Sprint(start+i)})
				}
				return page, nil
			})
			field := "Keys"
			if verb == "list-aliases" {
				field = "Aliases"
			}
			output := f.run(t, verb, "--page-size", "2", "--max-items", "3", "--query", "[length("+field+"),NextToken]", "--output", "text")
			if output != "3\tthird\n" || len(f.conn.calls) != 2 {
				t.Fatalf("%q calls=%d", output, len(f.conn.calls))
			}
			f.conn.calls = nil
			output = f.run(t, verb, "--starting-token", "third", "--page-size", "1", "--no-paginate", "--query", "length("+field+")", "--output", "text")
			if output != "1\n" || len(f.conn.calls) != 1 {
				t.Fatalf("resume: %q calls=%d", output, len(f.conn.calls))
			}
		})
	}
	f := newKMSFixture(t, func(string, proto.Message) (proto.Message, error) {
		return &kmsv1.ListKeysResponse{NextPageToken: "again"}, nil
	})
	if code := f.c.Run(context.Background(), []string{"kms", "list-keys"}); code == 0 || len(f.conn.calls) != 2 || f.out.Len() != 0 {
		t.Fatal("repeated token not rejected")
	}
}

func TestKMSWaitAndMutationErrors(t *testing.T) {
	for _, state := range []kmsv1.OperationState{kmsv1.OperationState_OPERATION_STATE_SUCCEEDED, kmsv1.OperationState_OPERATION_STATE_FAILED, kmsv1.OperationState_OPERATION_STATE_SUPERSEDED} {
		f := newKMSFixture(t, func(string, proto.Message) (proto.Message, error) {
			return &kmsv1.Operation{RequestId: kmsTestRequestID, State: state}, nil
		})
		code := f.c.Run(context.Background(), []string{"kms", "wait", "operation-succeeded", "--request-id", kmsTestRequestID})
		if (code == 0) != (state == kmsv1.OperationState_OPERATION_STATE_SUCCEEDED) || f.out.Len() != 0 {
			t.Fatalf("state=%v exit=%d", state, code)
		}
	}
	f := newKMSFixture(t, func(_ string, q proto.Message) (proto.Message, error) {
		state := kmsv1.OperationState_OPERATION_STATE_PENDING
		if _, ok := q.(*kmsv1.GetOperationRequest); ok {
			state = kmsv1.OperationState_OPERATION_STATE_SUCCEEDED
		}
		return &kmsv1.Operation{RequestId: kmsTestRequestID, OperationType: "CreateKey", ResultKeyUrn: kmsTestKey, State: state}, nil
	})
	if got := f.run(t, "create-key", "--wait", "--query", "Operation.State", "--output", "text"); got != "Succeeded\n" {
		t.Fatal(got)
	}
	if len(f.conn.calls) != 2 {
		t.Fatal("did not poll operation")
	}
	f = newKMSFixture(t, func(string, proto.Message) (proto.Message, error) {
		return &kmsv1.Operation{RequestId: kmsTestRequestID, State: kmsv1.OperationState_OPERATION_STATE_PENDING}, nil
	})
	before := time.Now()
	if code := f.c.Run(context.Background(), []string{"kms", "create-key", "--wait", "--timeout", "10ms"}); code == 0 || time.Since(before) > time.Second || !strings.Contains(f.out.String(), kmsTestRequestID) || !strings.Contains(f.errout.String(), "continues") {
		t.Fatalf("timeout exit=%d stdout=%s stderr=%s", code, f.out, f.errout)
	}
	f = newKMSFixture(t, func(string, proto.Message) (proto.Message, error) {
		return nil, status.Error(codes.Aborted, "REVISION_CONFLICT")
	})
	if code := f.c.Run(context.Background(), []string{"kms", "disable-key", "--key-id", kmsTestKey, "--expected-revision", "4", "--request-id", kmsTestRequestID}); code == 0 || len(f.conn.calls) != 1 || !strings.Contains(f.errout.String(), kmsTestRequestID) || f.out.Len() != 0 {
		t.Fatal("conflict retried or receipt information lost")
	}
}

func TestKMSFormatsAndOutputErrors(t *testing.T) {
	for _, format := range []string{"json", "yaml", "text", "table"} {
		f := newKMSFixture(t, func(string, proto.Message) (proto.Message, error) {
			return &kmsv1.KeyMetadata{KeyUrn: kmsTestKey, State: kmsv1.KeyState_KEY_STATE_ENABLED, Revision: 7}, nil
		})
		if got := f.run(t, "--output", format, "describe-key", "--key-id", kmsTestID); !strings.Contains(got, kmsTestKey) {
			t.Fatal(got)
		}
	}
	f := newKMSFixture(t, func(string, proto.Message) (proto.Message, error) {
		return &kmsv1.EncryptResponse{CiphertextBlob: []byte("cipher")}, nil
	})
	f.c.Stdout = kmsFailWriter{}
	if code := f.c.Run(context.Background(), []string{"kms", "encrypt", "--key-id", kmsTestID, "--plaintext", "aA=="}); code == 0 {
		t.Fatal("output failure swallowed")
	}
}

type kmsFailWriter struct{}

func (kmsFailWriter) Write([]byte) (int, error) { return 0, errors.New("write failed") }

func TestKMSDescribeAliasAndPermissionFailures(t *testing.T) {
	f := newKMSFixture(t, func(_ string, q proto.Message) (proto.Message, error) {
		switch r := q.(type) {
		case *kmsv1.GetAliasRequest:
			if r.AliasUrn != kmsAliasPrefix+"payments" {
				t.Fatal(r)
			}
			return &kmsv1.AliasMetadata{AliasUrn: r.AliasUrn, KeyUrn: kmsTestKey}, nil
		case *kmsv1.KeyRequest:
			if r.KeyUrn != kmsTestKey {
				t.Fatal(r)
			}
			return &kmsv1.KeyMetadata{KeyUrn: r.KeyUrn}, nil
		default:
			t.Fatalf("unexpected request %T", q)
			return nil, nil
		}
	})
	if got := f.run(t, "describe-key", "--key-id", "alias/payments", "--query", "KeyMetadata.KeyId", "--output", "text"); got != kmsTestKey+"\n" {
		t.Fatal(got)
	}
	for _, args := range [][]string{{"disable-key", "--key-id", kmsTestID}, {"update-alias", "--alias-name", "alias/payments", "--target-key-id", kmsTestID}} {
		f = newKMSFixture(t, func(string, proto.Message) (proto.Message, error) {
			return nil, status.Error(codes.PermissionDenied, "ACCESS_DENIED")
		})
		if code := f.c.Run(context.Background(), append([]string{"kms"}, args...)); code == 0 || len(f.conn.calls) != 1 || f.out.Len() != 0 {
			t.Fatal("mutation proceeded after failed metadata read")
		}
	}
}

func TestKMSUnboundedPaginationAndPageFailure(t *testing.T) {
	for _, fail := range []bool{false, true} {
		f := newKMSFixture(t, func(_ string, q proto.Message) (proto.Message, error) {
			request := q.(*kmsv1.ListKeysRequest)
			if request.PageToken == "" {
				return &kmsv1.ListKeysResponse{Keys: []*kmsv1.KeyMetadata{{KeyUrn: kmsTestKey}}, NextPageToken: "next"}, nil
			}
			if fail {
				return nil, status.Error(codes.Unavailable, "catalog unavailable")
			}
			return &kmsv1.ListKeysResponse{Keys: []*kmsv1.KeyMetadata{{KeyUrn: kmsTestKey}}}, nil
		})
		code := f.c.Run(context.Background(), []string{"kms", "list-keys", "--query", "length(Keys)", "--output", "text"})
		if fail {
			if code == 0 || f.out.Len() != 0 {
				t.Fatal("partial list emitted as successful output")
			}
		} else if code != 0 || f.out.String() != "2\n" {
			t.Fatalf("exit=%d output=%s", code, f.out)
		}
		if len(f.conn.calls) != 2 {
			t.Fatalf("calls=%d", len(f.conn.calls))
		}
	}
}
