package publiccli

import (
	"context"
	"fmt"
	"time"

	"github.com/spf13/cobra"
	"google.golang.org/protobuf/proto"

	kmsv1 "go.motiveiq.dev/platform/kms/api/v1"
)

const KMSEndpointEnv = "IQ_KMS_ENDPOINT"

type kmsOptions struct {
	iamOptions
	endpoint, binaryFormat string
	timeout                time.Duration
}

func (c *Command) kmsCommand() *cobra.Command {
	o := &kmsOptions{iamOptions: iamOptions{}}
	command := &cobra.Command{
		Use: "kms", Short: "Manage keys and encrypt data through MotiveIQ KMS.",
		Long: "AWS-style KMS commands using configured credentials and MotiveIQ IAM. Key IDs are UUIDs or MotiveIQ URNs; aliases start with alias/. Binary outputs are base64. See cmd/iq/KMS.md for API differences.",
	}
	c.addIAMFlags(command, &o.iamOptions)
	f := command.PersistentFlags()
	f.StringVar(&o.endpoint, "endpoint-url", c.Env(KMSEndpointEnv), "KMS HTTPS origin override (env: IQ_KMS_ENDPOINT).")
	f.StringVar(&o.binaryFormat, "cli-binary-format", "base64", "Binary inputs: base64 or raw-in-base64-out; fileb:// always reads raw bytes.")
	f.DurationVar(&o.timeout, "timeout", time.Minute, "Deadline for credentials and API calls, including pagination or waiting.")
	f.Bool("no-cli-pager", false, "Disable paging (iq always writes directly to stdout).")
	must(command.RegisterFlagCompletionFunc("cli-binary-format", fixedCompletions("base64", "raw-in-base64-out")))
	for _, verb := range []string{"encrypt", "decrypt", "re-encrypt", "generate-data-key", "generate-data-key-without-plaintext"} {
		command.AddCommand(c.kmsDataCommand(o, verb))
	}
	for _, verb := range kmsControlVerbs {
		command.AddCommand(c.kmsControlCommand(o, verb))
	}
	wait := &cobra.Command{Use: "wait", Short: "Wait for a management operation to succeed."}
	wait.AddCommand(c.kmsWaitCommand(o))
	command.AddCommand(wait)
	return command
}

func (o *kmsOptions) validate() (string, error) {
	if err := o.outputOptions.validate(); err != nil {
		return "", err
	}
	if o.timeout <= 0 {
		return "", fmt.Errorf("--timeout must be positive")
	}
	if o.binaryFormat != "base64" && o.binaryFormat != "raw-in-base64-out" {
		return "", fmt.Errorf("--cli-binary-format must be base64 or raw-in-base64-out")
	}
	// S3 and KMS both expose a TLS gRPC service behind an HTTPS origin.
	return s3Endpoint(o.endpoint)
}

func (c *Command) withKMS(ctx context.Context, o *kmsOptions, endpoint string, call func(context.Context, KMSClient) error) error {
	ctx, cancel := context.WithTimeout(ctx, o.timeout)
	defer cancel()
	cfg, err := c.LoadSDKConfig(ctx, o.Role)
	if err != nil {
		return err
	}
	defer cfg.Close()
	client, err := c.NewKMSFromConfig(cfg, endpoint)
	if err != nil {
		return err
	}
	return call(ctx, client)
}

func (c *Command) kmsDataCommand(o *kmsOptions, verb string) *cobra.Command {
	var key, source, blob, plaintext, spec, encryptionContext, sourceContext, destinationContext string
	var number uint32
	command := &cobra.Command{Use: verb, Short: map[string]string{
		"encrypt": "Encrypt up to 4096 bytes.", "decrypt": "Decrypt a KMS blob using its expected immutable key.",
		"re-encrypt":                          "Rewrap a KMS blob without returning plaintext.",
		"generate-data-key":                   "Generate a random data key and its wrapped copy.",
		"generate-data-key-without-plaintext": "Generate a wrapped data key without returning plaintext.",
	}[verb], Args: cobra.NoArgs}
	f := command.Flags()
	required := func(name string) { must(command.MarkFlagRequired(name)) }
	if verb == "re-encrypt" {
		f.StringVar(&source, "source-key-id", "", "Expected source key UUID or URN (required).")
		f.StringVar(&key, "destination-key-id", "", "Destination key UUID, URN, or alias/name.")
		f.StringVar(&sourceContext, "source-encryption-context", "", "Source context as key=value pairs, JSON, or file://JSON.")
		f.StringVar(&destinationContext, "destination-encryption-context", "", "Destination context as key=value pairs, JSON, or file://JSON.")
		f.String("source-encryption-algorithm", "SYMMETRIC_DEFAULT", "Only SYMMETRIC_DEFAULT is supported.")
		f.String("destination-encryption-algorithm", "SYMMETRIC_DEFAULT", "Only SYMMETRIC_DEFAULT is supported.")
		required("source-key-id")
		required("destination-key-id")
	} else {
		f.StringVar(&key, "key-id", "", "Key UUID or URN; encryption and generation also accept alias/name.")
		f.StringVar(&encryptionContext, "encryption-context", "", "Context as key=value pairs, JSON, or file://JSON.")
		required("key-id")
	}
	switch verb {
	case "encrypt":
		f.StringVar(&plaintext, "plaintext", "", "Base64 plaintext, or fileb://PATH for raw bytes.")
		required("plaintext")
	case "decrypt", "re-encrypt":
		f.StringVar(&blob, "ciphertext-blob", "", "Base64 KMS ciphertext, or fileb://PATH for raw bytes.")
		required("ciphertext-blob")
	default:
		f.StringVar(&spec, "key-spec", "", "Data key size: AES_256 (32 bytes).")
		f.Uint32Var(&number, "number-of-bytes", 0, "Data key size in bytes (1–1024).")
		command.MarkFlagsOneRequired("key-spec", "number-of-bytes")
		command.MarkFlagsMutuallyExclusive("key-spec", "number-of-bytes")
	}
	if verb == "encrypt" || verb == "decrypt" {
		f.String("encryption-algorithm", "SYMMETRIC_DEFAULT", "Only SYMMETRIC_DEFAULT is supported.")
	}
	command.RunE = func(cmd *cobra.Command, _ []string) error {
		endpoint, err := o.validate()
		if err != nil {
			return err
		}
		// Reject unsupported algorithms, including explicitly empty values.
		for _, flag := range []string{"encryption-algorithm", "source-encryption-algorithm", "destination-encryption-algorithm"} {
			if f.Changed(flag) {
				value, _ := f.GetString(flag)
				if value != "SYMMETRIC_DEFAULT" {
					return fmt.Errorf("--%s must be SYMMETRIC_DEFAULT", flag)
				}
			}
		}
		resolved, err := kmsKey(key, verb != "decrypt")
		if err != nil {
			return err
		}
		ctxMap, err := kmsContext(encryptionContext, "encryption-context")
		if err != nil {
			return err
		}
		var request proto.Message
		var sensitive []byte
		switch verb {
		case "encrypt":
			sensitive, err = kmsBlob(plaintext, "plaintext", o.binaryFormat, 4096)
			request = &kmsv1.EncryptRequest{Key: resolved, Plaintext: sensitive, EncryptionContext: ctxMap}
		case "decrypt", "re-encrypt":
			var ciphertext []byte
			ciphertext, err = kmsBlob(blob, "ciphertext-blob", o.binaryFormat, 8192)
			if err != nil {
				return err
			}
			if verb == "decrypt" {
				request = &kmsv1.DecryptRequest{KeyUrn: resolved, CiphertextBlob: ciphertext, EncryptionContext: ctxMap}
			} else {
				src, e := kmsKey(source, false)
				if e != nil {
					return fmt.Errorf("--source-key-id: %w", e)
				}
				srcCtx, e := kmsContext(sourceContext, "source-encryption-context")
				if e != nil {
					return e
				}
				dstCtx, e := kmsContext(destinationContext, "destination-encryption-context")
				if e != nil {
					return e
				}
				request = &kmsv1.ReEncryptRequest{SourceKeyUrn: src, DestinationKey: resolved, CiphertextBlob: ciphertext, SourceEncryptionContext: srcCtx, DestinationEncryptionContext: dstCtx}
			}
		default:
			q := &kmsv1.GenerateDataKeyRequest{Key: resolved, EncryptionContext: ctxMap}
			if f.Changed("key-spec") {
				if spec != "AES_256" {
					return fmt.Errorf("--key-spec must be AES_256; use --number-of-bytes for other sizes")
				}
				q.Size = &kmsv1.GenerateDataKeyRequest_KeySpec{KeySpec: kmsv1.DataKeySpec_DATA_KEY_SPEC_AES_256}
			} else {
				if number < 1 || number > 1024 {
					return fmt.Errorf("--number-of-bytes must be between 1 and 1024")
				}
				q.Size = &kmsv1.GenerateDataKeyRequest_NumberOfBytes{NumberOfBytes: number}
			}
			request = q
		}
		if err != nil {
			return err
		}
		defer clear(sensitive)
		return c.withKMS(cmd.Context(), o, endpoint, func(ctx context.Context, client KMSClient) error {
			var response proto.Message
			var err error
			switch verb {
			case "encrypt":
				response, err = client.Encrypt(ctx, request.(*kmsv1.EncryptRequest))
			case "decrypt":
				response, err = client.Decrypt(ctx, request.(*kmsv1.DecryptRequest))
			case "re-encrypt":
				response, err = client.ReEncrypt(ctx, request.(*kmsv1.ReEncryptRequest))
			case "generate-data-key":
				response, err = client.GenerateDataKey(ctx, request.(*kmsv1.GenerateDataKeyRequest))
			case "generate-data-key-without-plaintext":
				response, err = client.GenerateDataKeyWithoutPlaintext(ctx, request.(*kmsv1.GenerateDataKeyRequest))
			}
			if err != nil {
				return err
			}
			if secret, ok := response.(interface{ GetPlaintext() []byte }); ok {
				defer clear(secret.GetPlaintext())
			}
			return c.printKMS(o.outputOptions, verb, kmsResponse(response))
		})
	}
	return command
}
