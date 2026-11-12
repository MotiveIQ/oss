package publiccli

import (
	"encoding/json"
	"strings"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	kmsv1 "go.motiveiq.dev/platform/kms/api/v1"
)

func (c *Command) printKMS(options outputOptions, title string, value any) error {
	payload, err := json.Marshal(value)
	if err != nil {
		return err
	}
	defer clear(payload)
	return c.printOutput(options, title, payload, nil)
}

func kmsTime(value *timestamppb.Timestamp) any {
	if value == nil {
		return nil
	}
	return value.AsTime().UTC().Format(time.RFC3339Nano)
}

func kmsKeyMetadata(key *kmsv1.KeyMetadata) map[string]any {
	return map[string]any{
		"KeyId": key.GetKeyUrn(), "Description": key.GetDescription(), "KeySpec": key.GetKeySpec(), "KeyUsage": key.GetKeyUsage(),
		"KeyState": kmsState(strings.TrimPrefix(key.GetState().String(), "KEY_STATE_")), "Enabled": key.GetState() == kmsv1.KeyState_KEY_STATE_ENABLED,
		"Revision": key.GetRevision(), "ObservedRevision": key.GetObservedRevision(), "MaterialVersion": key.GetActiveMaterialVersion(),
		"RotationPeriodInDays": key.GetRotationPolicy().GetPeriodDays(), "LastRotationDate": kmsTime(key.GetLastRotationTime()),
		"NextRotationDate": kmsTime(key.GetNextRotationTime()), "DeletionDate": kmsTime(key.GetDeletionTime()),
		"PolicyRevision": key.GetPolicyRevision(), "AppliedPolicyRevision": key.GetAppliedPolicyRevision(), "AppliedPolicyHash": key.GetAppliedPolicyHash(),
		"Ready": key.GetReady(), "LastErrorCode": key.GetLastErrorCode(), "CreationDate": kmsTime(key.GetCreateTime()), "UpdateDate": kmsTime(key.GetUpdateTime()),
	}
}

func kmsAliasMetadata(alias *kmsv1.AliasMetadata) map[string]any {
	return map[string]any{"AliasName": "alias/" + strings.TrimPrefix(alias.GetAliasUrn(), kmsAliasPrefix), "AliasUrn": alias.GetAliasUrn(), "TargetKeyId": alias.GetKeyUrn(), "Revision": alias.GetRevision()}
}

func kmsState(value string) string {
	words := strings.Split(strings.ToLower(value), "_")
	for i, word := range words {
		if len(word) > 0 {
			words[i] = strings.ToUpper(word[:1]) + word[1:]
		}
	}
	return strings.Join(words, "")
}

// AWS field names keep common --query expressions usable. Identity values are
// MotiveIQ URNs; no AWS ARN is invented. Byte slices marshal as base64 strings.
func kmsResponse(message proto.Message) map[string]any {
	material := func(ref *kmsv1.KeyMaterialRef) map[string]any {
		return map[string]any{"KeyId": ref.GetKeyUrn(), "MaterialVersion": ref.GetMaterialVersion()}
	}
	switch m := message.(type) {
	case *kmsv1.EncryptResponse:
		out := material(m.Key)
		out["CiphertextBlob"] = m.CiphertextBlob
		out["EncryptionAlgorithm"] = "SYMMETRIC_DEFAULT"
		return out
	case *kmsv1.DecryptResponse:
		out := material(m.Key)
		out["Plaintext"] = m.Plaintext
		out["EncryptionAlgorithm"] = "SYMMETRIC_DEFAULT"
		out["Purpose"] = strings.TrimPrefix(m.Purpose.String(), "CIPHERTEXT_PURPOSE_")
		return out
	case *kmsv1.GenerateDataKeyResponse:
		out := material(m.Key)
		out["Plaintext"] = m.Plaintext
		out["CiphertextBlob"] = m.CiphertextBlob
		return out
	case *kmsv1.GenerateDataKeyWithoutPlaintextResponse:
		out := material(m.Key)
		out["CiphertextBlob"] = m.CiphertextBlob
		return out
	case *kmsv1.ReEncryptResponse:
		out := material(m.Destination)
		out["SourceKeyId"] = m.Source.GetKeyUrn()
		out["SourceMaterialVersion"] = m.Source.GetMaterialVersion()
		out["CiphertextBlob"] = m.CiphertextBlob
		out["SourceEncryptionAlgorithm"] = "SYMMETRIC_DEFAULT"
		out["DestinationEncryptionAlgorithm"] = "SYMMETRIC_DEFAULT"
		return out
	case *kmsv1.KeyMetadata:
		return map[string]any{"KeyMetadata": kmsKeyMetadata(m)}
	case *kmsv1.AliasMetadata:
		return kmsAliasMetadata(m)
	case *kmsv1.GetKeyPolicyResponse:
		return map[string]any{"Policy": m.DesiredDocument, "PolicyName": "default", "AppliedPolicy": m.AppliedDocument, "AppliedPolicyHash": m.AppliedHash, "Revision": m.DesiredRevision, "AppliedRevision": m.AppliedRevision}
	case *kmsv1.GetRotationPolicyResponse:
		return map[string]any{"KeyRotationEnabled": true, "RotationPeriodInDays": m.RotationPolicy.GetPeriodDays(), "LastRotationDate": kmsTime(m.LastRotationTime), "NextRotationDate": kmsTime(m.NextRotationTime)}
	case *kmsv1.Operation:
		out := map[string]any{"Operation": map[string]any{
			"RequestId": m.RequestId, "OperationType": m.OperationType, "ResourceUrns": m.ResourceUrns,
			"AcceptedRevision": m.AcceptedRevision, "State": kmsState(strings.TrimPrefix(m.State.String(), "OPERATION_STATE_")),
			"ErrorCode": m.ErrorCode, "SafeErrorMessage": m.SafeErrorMessage, "CreationDate": kmsTime(m.CreateTime), "UpdateDate": kmsTime(m.UpdateTime),
		}}
		if m.ResultKeyUrn != "" {
			out["KeyId"] = m.ResultKeyUrn
		}
		// Creation receipts know the allocated identifier, but do not claim that
		// reconciliation has finished. DescribeKey supplies complete key metadata.
		if m.OperationType == "CreateKey" {
			out["KeyMetadata"] = map[string]any{"KeyId": m.ResultKeyUrn}
		}
		if m.ResultAlias != nil {
			out["Alias"] = kmsAliasMetadata(m.ResultAlias)
		}
		return out
	default:
		panic("unexpected KMS response type")
	}
}
