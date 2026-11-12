package publiccli

import (
	"errors"

	motiveiq "go.motiveiq.dev/platform/iam/sdk"
	sm "go.motiveiq.dev/platform/secretsmanager/api/v1"
)

type SecretsManagerClient = sm.SecretsManagerClient

func newSecretsManagerFromConfig(cfg *motiveiq.Config, endpoint string) (SecretsManagerClient, error) {
	if cfg == nil {
		return nil, errors.New("nil MotiveIQ config")
	}
	return sm.NewFromConfig(cfg, func(o *sm.ClientOptions) { o.BaseEndpoint = endpoint }), nil
}

func NewSecretsManagerFromConfig(cfg *motiveiq.Config, endpoint string) (SecretsManagerClient, error) {
	return newSecretsManagerFromConfig(cfg, endpoint)
}
