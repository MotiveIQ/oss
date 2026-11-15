package motiveiq_test

import (
	"fmt"
	"strings"
	"testing"

	_ "go.motiveiq.dev/platform/iam/api/v1"
	_ "go.motiveiq.dev/platform/iam/sdk"
	_ "go.motiveiq.dev/platform/kms/api/v1"
	_ "go.motiveiq.dev/platform/s3/api/v1"
	_ "go.motiveiq.dev/platform/secretsmanager/api/v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/descriptorpb"
)

// A package graph alone cannot detect a private service placed in an otherwise
// public proto package. Check all descriptors linked by the public clients.
var publicServices = map[protoreflect.FullName]bool{
	"motiveiq.iam.v1.IAM":                       true,
	"motiveiq.iam.v1.ControlPlane":              true,
	"motiveiq.iam.v1.STS":                       true,
	"motiveiq.kms.v1.ControlPlane":              true,
	"motiveiq.kms.v1.DataPlane":                 true,
	"motiveiq.s3.v1.ControlPlane":               true,
	"motiveiq.s3.v1.DataPlane":                  true,
	"motiveiq.secretsmanager.v1.SecretsManager": true,
}

func checkPublicDescriptor(fd protoreflect.FileDescriptor) error {
	if strings.HasPrefix(fd.Path(), "platform/iam/pdp/") || strings.HasPrefix(fd.Path(), "platform/iam/private/") {
		return fmt.Errorf("private IAM descriptor: %s", fd.Path())
	}
	for i := 0; i < fd.Services().Len(); i++ {
		service := fd.Services().Get(i)
		name := service.FullName()
		if strings.HasPrefix(string(name), "motiveiq.") && !publicServices[name] {
			return fmt.Errorf("unreviewed service: %s", name)
		}
		if name == "motiveiq.iam.v1.STS" {
			for j := 0; j < service.Methods().Len(); j++ {
				method := service.Methods().Get(j).Name()
				if method != "AssumeRoleWithWebIdentity" && method != "GetCallerIdentity" {
					return fmt.Errorf("unreviewed public STS method: %s", method)
				}
			}
		}
	}
	for i := 0; i < fd.Enums().Len(); i++ {
		if fd.Enums().Get(i).FullName() == "motiveiq.iam.v1.SourcePayloadVerification" {
			return fmt.Errorf("private delegation enum: %s", fd.Enums().Get(i).FullName())
		}
	}
	var checkMessages func(protoreflect.MessageDescriptors) error
	checkMessages = func(messages protoreflect.MessageDescriptors) error {
		for i := 0; i < messages.Len(); i++ {
			message := messages.Get(i)
			switch message.FullName() {
			case "motiveiq.iam.v1.SubjectAuthentication", "motiveiq.iam.v1.VerifiedRequestBinding", "motiveiq.iam.v1.DelegatedSubjectAuthentication", "motiveiq.iam.v1.AuthorizeRequest", "motiveiq.iam.v1.AuthorizeResponse", "motiveiq.iam.v1.AuthorizeDelegationRequest", "motiveiq.iam.v1.AuthorizeDelegationResponse":
				return fmt.Errorf("private authorization message: %s", message.FullName())
			case "motiveiq.iam.v1.SourceResourceSelector", "motiveiq.iam.v1.DerivedSourceResource", "motiveiq.iam.v1.SourceRequestEvidence", "motiveiq.iam.v1.GRPCRequestEvidence", "motiveiq.iam.v1.HTTPRequestEvidence", "motiveiq.iam.v1.VerifiedSourceRequest", "motiveiq.iam.v1.SourceRequestContext", "motiveiq.iam.v1.RequestIdentity", "motiveiq.iam.v1.GRPCRequestIdentity", "motiveiq.iam.v1.HTTPRequestIdentity", "motiveiq.iam.v1.SessionReference", "motiveiq.iam.v1.SourceCatalogAssertions", "motiveiq.iam.v1.DelegationReference", "motiveiq.iam.v1.DelegationTarget", "motiveiq.iam.v1.DelegationScope", "motiveiq.iam.v1.IssueDelegationTokenRequest", "motiveiq.iam.v1.IssueDelegationTokenResponse":
				return fmt.Errorf("private delegation message: %s", message.FullName())
			}
			if err := checkMessages(message.Messages()); err != nil {
				return err
			}
		}
		return nil
	}
	return checkMessages(fd.Messages())
}

func TestPublicDescriptorsExcludePrivateAuthorization(t *testing.T) {
	seen := map[protoreflect.FullName]bool{}
	protoregistry.GlobalFiles.RangeFiles(func(fd protoreflect.FileDescriptor) bool {
		if err := checkPublicDescriptor(fd); err != nil {
			t.Error(err)
		}
		for i := 0; i < fd.Services().Len(); i++ {
			seen[fd.Services().Get(i).FullName()] = true
		}
		return true
	})
	for name := range publicServices {
		if !seen[name] {
			t.Errorf("public contract not linked: %s", name)
		}
	}
}

func TestDescriptorGuardRejectsPrivateSymbolsInPublicPackage(t *testing.T) {
	for _, tc := range []struct {
		name    string
		service bool
	}{{"PDP", true}, {"PrivateSTS", true}, {"SubjectAuthentication", false}, {"VerifiedRequestBinding", false}, {"DelegatedSubjectAuthentication", false}, {"IssueDelegationTokenRequest", false}, {"DelegationScope", false}} {
		t.Run(tc.name, func(t *testing.T) {
			descriptor := &descriptorpb.FileDescriptorProto{Name: proto.String("platform/iam/api/v1/accidental.proto"), Package: proto.String("motiveiq.iam.v1"), Syntax: proto.String("proto3")}
			if tc.service {
				descriptor.Service = []*descriptorpb.ServiceDescriptorProto{{Name: proto.String(tc.name)}}
			} else {
				descriptor.MessageType = []*descriptorpb.DescriptorProto{{Name: proto.String(tc.name)}}
			}
			fd, err := protodesc.NewFile(descriptor, nil)
			if err != nil {
				t.Fatal(err)
			}
			if err := checkPublicDescriptor(fd); err == nil {
				t.Fatal("private symbol accepted")
			}
		})
	}
}

func TestDescriptorGuardRejectsLegacySTSIssuance(t *testing.T) {
	fd, err := protodesc.NewFile(&descriptorpb.FileDescriptorProto{
		Name: proto.String("platform/iam/api/v1/accidental.proto"), Package: proto.String("motiveiq.iam.v1"), Syntax: proto.String("proto3"),
		MessageType: []*descriptorpb.DescriptorProto{{Name: proto.String("Empty")}},
		Service: []*descriptorpb.ServiceDescriptorProto{{Name: proto.String("STS"), Method: []*descriptorpb.MethodDescriptorProto{{
			Name: proto.String("IssueDelegationToken"), InputType: proto.String(".motiveiq.iam.v1.Empty"), OutputType: proto.String(".motiveiq.iam.v1.Empty"),
		}}}},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := checkPublicDescriptor(fd); err == nil {
		t.Fatal("legacy public STS issuance accepted")
	}
}
