package publiccli

import (
	"errors"

	motiveiq "github.com/MotiveIQ/public/platform/iam/sdk"
	kmsv1 "github.com/MotiveIQ/public/platform/kms/api/v1"
)

// KMSClient keeps both APIs on the same proof-bound SDK configuration.
type KMSClient interface {
	kmsv1.DataPlaneClient
	kmsv1.ControlPlaneClient
}

type kmsClient struct {
	kmsv1.DataPlaneClient
	kmsv1.ControlPlaneClient
}

func newKMSFromConfig(cfg *motiveiq.Config, endpoint string) (KMSClient, error) {
	if cfg == nil {
		return nil, errors.New("nil MotiveIQ config")
	}
	option := func(o *kmsv1.ClientOptions) { o.BaseEndpoint = endpoint }
	return &kmsClient{
		DataPlaneClient:    kmsv1.NewFromConfig(cfg, option),
		ControlPlaneClient: kmsv1.NewControlPlaneFromConfig(cfg, option),
	}, nil
}

func NewKMSFromConfig(cfg *motiveiq.Config, endpoint string) (KMSClient, error) {
	return newKMSFromConfig(cfg, endpoint)
}
