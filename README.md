# MotiveIQ APIs and CLI

Client packages for MotiveIQ IAM/STS, S3, KMS, and Secrets Manager. This repository
is synchronized from MotiveIQ's monorepo by Copybara. Submit source changes in the
monorepo; direct changes here stop automatic synchronization.

## Build and test

Clone the repository and install [Bazelisk](https://github.com/bazelbuild/bazelisk):

```sh
git clone https://github.com/MotiveIQ/oss.git
cd oss
bazel build //cmd/iq //cmd/iq/oidc:iq-oidc
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
go build -o iq-oidc ./cmd/iq/oidc
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

Configure an external OIDC token source and an IAM role in
`~/.config/iq/config.toml` (or `IQ_CONFIG_FILE`):

```toml
[profiles.default]
role_urn = "urn:motiveiq:iam:role/YOUR_ROLE"
web_identity_source = "external"

[web_identity_sources.external]
type = "file"
[web_identity_sources.external.config]
path = "/absolute/path/to/oidc-token"
```

```sh
iq --help
iq sts get-caller-identity
iq --profile default s3 ls
```

Your administrator supplies the role and its trust relationship. Repository
access does not grant API permissions. API commands include IAM, STS, S3, KMS,
and Secrets Manager. This distribution has no company-specific `login` command;
`whoami` has been removed in favor of `sts get-caller-identity`.

Profiles separate role selection from external-token acquisition. Optional
`sts_endpoint` defaults to `api.motiveiq.net:443`. `--role` overrides only the
selected role. A named `--profile` (or `IQ_PROFILE`) takes precedence over
environment workload identity. Otherwise `IQ_WEB_IDENTITY_TOKEN_FILE` and
`IQ_ROLE_URN` select workload identity; absent those, the `default` profile
is selected. Partial environment configuration is an error. Failed sources never
fall back to another identity. `XDG_CONFIG_HOME` changes the config base directory.

A `process` source uses a command array in its config table:

```toml
[web_identity_sources.external]
type = "process"
[web_identity_sources.external.config]
command = ["/absolute/path/to/helper", "token"]
```

Commands can use an absolute executable path or a name on `PATH`. Relative
executable paths and implicit current-directory lookup are rejected. The
noninteractive helper runs without a shell and returns one JSON object:

```json
{"version":1,"token":"EXTERNAL_OIDC_TOKEN","expires_at":"2030-01-01T00:00:00Z"}
```

`expires_at` is optional RFC 3339 metadata and must be in the future if present.
The helper owns external-token refresh. It is invoked on STS exchanges and cache
lookups in new CLI processes. Output is limited to 1 MiB; execution respects
cancellation and a 30-second maximum (the SDK exchange may impose a shorter
deadline). Helper stdout/stderr are never included in failure messages. Perform
interactive authentication separately through your provider. An optional
`login_command` can be invoked explicitly by an application; token retrieval
never runs it.

The SDK owns role assumption, session/proof-key caching, refresh, and request
signing. Helpers only supply external tokens; they do not handle IAM proof keys.
Use `platform/iam/sdk/config.Load` for shared profile resolution, or `Resolver` to
register additional web-identity providers. Without an explicit profile,
`IQ_ROLE_URN` and `IQ_WEB_IDENTITY_TOKEN_FILE` select the workload identity
before the default local profile. Webhook-configured workloads need no TOML
file or interactive login. The SDK rereads the projected token on refresh.
Legacy `MOTIVEIQ_*` workload aliases remain supported during migration, with
`IQ_*` taking precedence. No human role is selected implicitly.
The monorepo installer and its developer configuration file are not included.

The Go SDK is `go.motiveiq.dev/platform/iam/sdk`. API schemas and
generated clients live under `platform/{iam,s3,kms,secretsmanager}/api/v1`.
Protobuf service identities and wire formats match MotiveIQ's deployed services.
Server implementations and the private policy-decision API are not included.


## Browser OIDC helper

The standalone `iq-oidc` executable uses discovery and the native authorization
code flow with PKCE S256. Register a public client at your issuer and configure:

```toml
[web_identity_sources.external]
type = "process"
[web_identity_sources.external.config]
command = ["iq-oidc", "token", "browser"]
login_command = ["iq-oidc", "login", "browser"]

[web_identity_sources.browser]
type = "oidc"
[web_identity_sources.browser.config]
issuer = "https://issuer.example/"
client_id = "YOUR_REGISTERED_CLIENT"
scopes = ["openid", "offline_access"]
callback_port = 0
```

Run `iq-oidc login browser` explicitly, then use the normal `iq` API commands.
Discovery must match the issuer exactly. The helper verifies the ID token and
returns it for IAM federation; the IAM administrator must trust that issuer and
client audience. It never selects a role or handles IAM proof keys. The OIDC
library is `coreos/go-oidc`, with `golang.org/x/oauth2` for exchanges and PKCE.

The token cache lives under `$XDG_CACHE_HOME/iq/oidc/` (default
`~/.cache/iq/oidc/`), with private permissions, per-source binding, locked refresh,
and atomic replacement. Optional absolute `token_file` selects another cache
file in a private directory. Refresh tokens are optional; refresh responses may
omit ID tokens, in which case expiration eventually requires explicit login.
Token retrieval never opens a browser. Use `iq-oidc access-token browser` only
when explicitly integrating an OAuth access-token consumer.

Provider extensions belong in `authorization_params`; reserved flow parameters
cannot be overridden. Optional `access_token_export_file` writes a process
locator for legacy OAuth consumers, without copying refresh credentials. Relative
paths are rooted in `XDG_CONFIG_HOME`; this option is unnecessary for IAM.
No MotiveIQ issuer, client registration, or role is built into this helper.
