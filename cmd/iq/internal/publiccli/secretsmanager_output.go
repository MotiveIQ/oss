package publiccli

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"strconv"
	"strings"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	sm "github.com/MotiveIQ/public/platform/secretsmanager/api/v1"
)

func secretDate(out map[string]any, field string, value *timestamppb.Timestamp) {
	if value != nil {
		out[field] = value.AsTime().UTC().Format(time.RFC3339Nano)
	}
}

func secretMetadata(m *sm.SecretMetadata) map[string]any {
	out := map[string]any{
		"URN": m.GetUrn(), "Name": m.GetName(), "Description": m.GetDescription(),
		"KmsKeyId": m.GetKmsKeyUrn(), "Revision": m.GetRevision(),
		"State":            strings.TrimPrefix(m.GetState().String(), "SECRET_STATE_"),
		"CurrentVersionId": m.GetCurrentVersionId(),
	}
	secretDate(out, "CreatedDate", m.GetCreateTime())
	secretDate(out, "LastChangedDate", m.GetUpdateTime())
	secretDate(out, "DeletionDate", m.GetDeletionTime())
	return out
}

func secretVersion(m *sm.SecretVersionMetadata) map[string]any {
	out := map[string]any{
		"URN": m.GetSecretUrn(), "VersionId": m.GetVersionId(), "Current": m.GetCurrent(),
		"ValueKind": strings.TrimPrefix(m.GetValueKind().String(), "SECRET_VALUE_KIND_"), "ValueSizeBytes": m.GetValueSizeBytes(),
	}
	secretDate(out, "CreatedDate", m.GetCreateTime())
	return out
}

// Keep AWS query vocabulary where it describes this API; URN identifies a
// MotiveIQ resource, and Current is a pointer rather than an AWS version stage.
func secretResponse(message proto.Message) map[string]any {
	switch m := message.(type) {
	case *sm.SecretMetadata:
		return secretMetadata(m)
	case *sm.CreateSecretResponse:
		out := secretMetadata(m.Secret)
		out["VersionId"] = m.Version.GetVersionId()
		return out
	case *sm.PutSecretValueResponse:
		out := secretMetadata(m.Secret)
		out["VersionId"] = m.Version.GetVersionId()
		return out
	case *sm.GetSecretValueResponse:
		out := map[string]any{"URN": m.SecretUrn, "VersionId": m.VersionId}
		secretDate(out, "CreatedDate", m.CreateTime)
		switch value := m.GetValue().GetValue().(type) {
		case *sm.SecretValue_StringValue:
			out["SecretString"] = value.StringValue
		case *sm.SecretValue_BinaryValue:
			out["SecretBinary"] = value.BinaryValue
		}
		return out
	default:
		panic("unexpected Secrets Manager response")
	}
}

func (c *Command) printSecretsManager(options outputOptions, title string, result map[string]any) error {
	payload, err := json.Marshal(result)
	if err != nil {
		return err
	}
	defer clear(payload)
	if options.Output != outputTable || options.query != nil {
		return c.printOutput(options, title, payload, nil)
	}
	// Default tables show useful columns, with a separate copyable continuation
	// token. Queries always operate on the full response before formatting.
	var buffer bytes.Buffer
	switch {
	case result["SecretList"] != nil:
		writeIAMTable(&buffer, title, secretListView(result["SecretList"].([]map[string]any), []string{"Name", "State", "Revision", "URN"}))
	case result["Versions"] != nil:
		writeIAMTable(&buffer, title, secretListView(result["Versions"].([]map[string]any), []string{"VersionId", "Current", "ValueKind", "ValueSizeBytes", "CreatedDate"}))
	default:
		var fields []iamField
		for _, key := range []string{"Name", "URN", "State", "KmsKeyId", "Revision", "CurrentVersionId", "VersionId", "CreatedDate", "LastChangedDate", "DeletionDate", "Description", "ClientRequestToken", "SecretString", "SecretBinary"} {
			if value, ok := result[key]; ok {
				// Use JSON's base64 representation of bytes in tables too.
				if b, ok := value.([]byte); ok {
					value = base64.StdEncoding.EncodeToString(b)
				}
				fields = append(fields, iamField{key, secretTableCell(value)})
			}
		}
		writeIAMTable(&buffer, title, iamObjectView(fields, "Description", "SecretString", "SecretBinary"))
	}
	if token, ok := result["NextToken"].(string); ok {
		writeIAMTable(&buffer, "Pagination", iamObjectView([]iamField{{"NextToken", token}}))
	}
	_, err = buffer.WriteTo(c.Stdout)
	return err
}

func secretTableCell(value any) string {
	// Escape newlines and terminal control sequences; JSON/text retain the value.
	quoted := strconv.QuoteToGraphic(iamQueryScalar(value))
	return quoted[1 : len(quoted)-1]
}

func secretListView(items []map[string]any, fields []string) iamView {
	rows := make([][]string, 0, len(items))
	for _, item := range items {
		row := make([]string, 0, len(fields))
		for _, field := range fields {
			row = append(row, secretTableCell(item[field]))
		}
		rows = append(rows, row)
	}
	return iamListView(fields, rows)
}
