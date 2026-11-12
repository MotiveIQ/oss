package publiccli

import (
	"context"
	"errors"
	"io"

	motiveiq "go.motiveiq.dev/platform/iam/sdk"
	s3v1 "go.motiveiq.dev/platform/s3/api/v1"
	"google.golang.org/grpc"
)

// S3Client combines the control plane with the shared transfer helpers, which
// own signed upload completion and download stream validation.
type S3Client interface {
	ListBuckets(context.Context, *s3v1.ListBucketsRequest, ...grpc.CallOption) (*s3v1.ListBucketsResponse, error)
	GetBucket(context.Context, *s3v1.GetBucketRequest, ...grpc.CallOption) (*s3v1.HeadBucketResponse, error)
	CreateBucket(context.Context, *s3v1.CreateBucketRequest, ...grpc.CallOption) (*s3v1.CreateBucketResponse, error)
	DeleteBucket(context.Context, *s3v1.DeleteBucketRequest, ...grpc.CallOption) (*s3v1.DeleteBucketResponse, error)
	GetMutation(context.Context, *s3v1.GetMutationRequest, ...grpc.CallOption) (*s3v1.Mutation, error)
	ListObjects(context.Context, *s3v1.ListObjectsRequest, ...grpc.CallOption) (*s3v1.ListObjectsResponse, error)
	HeadObject(context.Context, *s3v1.HeadObjectRequest, ...grpc.CallOption) (*s3v1.HeadObjectResponse, error)
	Download(context.Context, *s3v1.GetObjectRequest, ...grpc.CallOption) (*s3v1.DownloadOutput, error)
	Upload(context.Context, *s3v1.PutObjectHeader, io.Reader, ...grpc.CallOption) (*s3v1.PutObjectResponse, error)
	DeleteObject(context.Context, *s3v1.DeleteObjectRequest, ...grpc.CallOption) (*s3v1.DeleteObjectResponse, error)
}

type s3Client struct {
	*s3v1.Client
	s3v1.ControlPlaneClient
}

func newS3FromConfig(cfg *motiveiq.Config, endpoint string) (S3Client, error) {
	if cfg == nil {
		return nil, errors.New("nil MotiveIQ config")
	}
	option := func(o *s3v1.ClientOptions) { o.BaseEndpoint = endpoint }
	return &s3Client{s3v1.NewFromConfig(cfg, option), s3v1.NewControlPlaneFromConfig(cfg, option)}, nil
}

func NewS3FromConfig(cfg *motiveiq.Config, endpoint string) (S3Client, error) {
	return newS3FromConfig(cfg, endpoint)
}
