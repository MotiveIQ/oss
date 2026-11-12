# MotiveIQ APIs and CLI

Client packages for MotiveIQ IAM/STS, S3, KMS, and Secrets Manager. This repository
is synchronized from MotiveIQ's monorepo by Copybara. Submit source changes in the
monorepo; direct changes here stop automatic synchronization.

## Build and test

Install [Bazelisk](https://github.com/bazelbuild/bazelisk), then:

```sh
bazel build //cmd/iq
bazel test //...
bazel run //cmd/iq -- --help
```

Bazel downloads pinned public toolchains and dependencies. Building requires no
monorepo checkout, private registry, remote execution service, or API credentials.
The first build needs internet access. Linux and macOS are supported.

Generated protobuf Go clients are also included for ordinary Go consumers:

```sh
go test ./...
go install github.com/MotiveIQ/public/cmd/iq@latest
```

If the repository is private, configure GitHub access and set
`GOPRIVATE=github.com/MotiveIQ/public` before fetching it with Go.

## Use

```sh
iq --help
iq login --help
iq whoami --role urn:motiveiq:iam:role/YOUR_ROLE
iq s3 --role urn:motiveiq:iam:role/YOUR_ROLE --help
```

Your MotiveIQ administrator supplies the role and its trust relationship.
Repository access does not grant API permissions. The CLI includes login,
whoami, IAM, STS, S3, KMS, and Secrets Manager commands. Run a command's `--help`
for its endpoint and authentication flags.

The Go SDK is `github.com/MotiveIQ/public/platform/iam/sdk`. API schemas and
generated clients live under `platform/{iam,s3,kms,secretsmanager}/api/v1`.
Protobuf service identities and wire formats match MotiveIQ's deployed services.
Server implementations and the private policy-decision API are not included.
