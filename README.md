# MotiveIQ APIs and CLI

Client packages for MotiveIQ IAM/STS, S3, KMS, and Secrets Manager. This repository
is synchronized from MotiveIQ's monorepo by Copybara. Submit source changes in the
monorepo; direct changes here stop automatic synchronization.

## Build and test

Clone the repository and install [Bazelisk](https://github.com/bazelbuild/bazelisk):

```sh
git clone https://github.com/MotiveIQ/oss.git
cd oss
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
go install ./cmd/iq
```

These commands run from the clone. The Go module is `go.motiveiq.dev`, shared
with the source monorepo. Go discovery metadata for that domain is not configured
by this export, so fetching by module path or using
`go install go.motiveiq.dev/cmd/iq@latest` is not supported yet.
If the repository is private, GitHub access is required to clone it.

To use the SDK in another Go module before discovery is configured, add a local
replacement pointing at your clone:

```sh
go mod edit -replace=go.motiveiq.dev=/absolute/path/to/oss
go get go.motiveiq.dev/platform/iam/sdk
```

The local replacement is a development setup; it does not propagate to consumers
of your module. Published versions of `go.motiveiq.dev` will come from this
repository, with tags and commit versions referring to the exported history.

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

The Go SDK is `go.motiveiq.dev/platform/iam/sdk`. API schemas and
generated clients live under `platform/{iam,s3,kms,secretsmanager}/api/v1`.
Protobuf service identities and wire formats match MotiveIQ's deployed services.
Server implementations and the private policy-decision API are not included.
