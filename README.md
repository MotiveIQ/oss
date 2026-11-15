# MotiveIQ APIs and CLI

Go clients and the `iq` CLI for MotiveIQ IAM/STS, S3, KMS, and Secrets Manager.
This repository is synchronized from MotiveIQ's monorepo by Copybara; submit
source changes there, because direct changes here stop synchronization.

## Install

Install [Bazelisk](https://github.com/bazelbuild/bazelisk), then bootstrap from
this checkout using the same command as the monorepo:

```sh
git clone https://github.com/MotiveIQ/oss.git
cd oss
bazel run //cmd/iq -- install iq
export PATH="$HOME/.local/bin:$PATH"
```

This installs `iq` and its `iq-oidc` browser helper in `~/.local/bin`. Add that
directory to your shell's `PATH` permanently. Bazel downloads the pinned public
toolchains and dependencies; no Go installation, monorepo access, private
registry, or API credentials are needed. Linux and macOS are supported.
Run the same command from the updated checkout to upgrade.

The OSS package leaves your configuration to you. The monorepo's package uses
the same install/login interfaces and additionally supplies MotiveIQ's developer
configuration, preserving an existing configuration. Neither CLI chooses a
human role implicitly.

## Configure browser login

First, arrange the two sides of federation:

- At your OIDC issuer, register a public/native client using authorization code
  with PKCE S256 and the redirect URI `http://127.0.0.1:48195/callback`.
- Have a MotiveIQ administrator register that issuer and client audience, give
  the desired subjects permission to assume a role through its trust policy,
  and grant the role its API permissions. Obtain the role URN from them.

Create `~/.config/iq/config.toml` with your issuer, client ID, and role:

```toml
[profiles.default]
role_urn = "urn:motiveiq:iam:role/YOUR_ROLE"
web_identity_source = "browser-login"

[web_identity_sources.browser-login]
type = "process"
[web_identity_sources.browser-login.config]
command = ["iq-oidc", "token", "browser"]
login_command = ["iq-oidc", "login", "browser"]

[web_identity_sources.browser]
type = "oidc"
[web_identity_sources.browser.config]
issuer = "https://issuer.example/"
client_id = "YOUR_REGISTERED_CLIENT"
scopes = ["openid", "offline_access"]
callback_port = 48195
```

```sh
iq login
iq sts get-caller-identity
iq s3 ls
```

`iq login --profile NAME` explicitly authenticates the selected profile.
Subsequent CLI and SDK calls retrieve tokens without opening a browser. The
helper returns a verified **ID token** for IAM federation; the SDK assumes the
role, refreshes IAM sessions, and signs requests. Repository access grants no
API permissions. The CLI's IAM commands inspect configuration; authorized
administrators can provision providers, roles, and policies through the Go API.

Use the issuer URL, not its discovery-document URL; discovery must match the
issuer exactly. The issuer must advertise HTTPS authorization, token, and JWKS
endpoints and support public clients and PKCE S256. The ID token must have the
client ID as its sole audience. Match `callback_port` to your registered redirect;
`0` chooses a random port for providers that permit variable loopback ports.
`offline_access` requests refresh tokens and consent; omit it if unsupported.
Refresh tokens are optional, and missing refreshed ID tokens eventually require
another explicit login.

## Use the Go SDK

Use Go 1.27.1 or newer with standard proxy and checksum settings. The public
module is `go.motiveiq.dev`; no GitHub credentials, `GOPRIVATE`, or `replace`
directive are required:

```sh
go get go.motiveiq.dev/platform/iam/sdk@latest
```

The SDK shares the CLI's profiles and token sources. For example, after login:

```go
package main

import (
    "context"
    "fmt"
    "log"

    iamv1 "go.motiveiq.dev/platform/iam/api/v1"
    sdkconfig "go.motiveiq.dev/platform/iam/sdk/config"
)

func main() {
    ctx := context.Background()
    cfg, err := sdkconfig.Load(ctx, "")
    if err != nil { log.Fatal(err) }
    defer cfg.Close()
    identity, err := iamv1.NewSTSFromConfig(cfg).GetCallerIdentity(ctx, &iamv1.GetCallerIdentityRequest{})
    if err != nil { log.Fatal(err) }
    fmt.Println(identity.GetRoleUrn())
}
```

For unattended workloads, provide a rotating raw OIDC token file instead:

```sh
export IQ_ROLE_URN="urn:motiveiq:iam:role/YOUR_WORKLOAD_ROLE"
export IQ_WEB_IDENTITY_TOKEN_FILE="/absolute/path/to/oidc-token"
```

The same `sdkconfig.Load` call works without TOML or browser login. The SDK
rereads the file on session refresh; your issuer/workload platform supplies and
rotates it. Applications can also supply a `WebIdentityTokenProvider` or register
additional sources with `sdkconfig.Resolver`. Helpers acquire external tokens;
the SDK owns IAM sessions, proof keys, refresh, and request signing.

## Configuration reference

- `IQ_CONFIG_FILE` overrides the file location; otherwise `XDG_CONFIG_HOME`
  selects the config base directory (default `~/.config`).
- `--profile` / `IQ_PROFILE` selects a profile before workload environment
  identity. Without an explicit profile, `IQ_ROLE_URN` and
  `IQ_WEB_IDENTITY_TOKEN_FILE` take precedence over the `default` profile.
  Partial configuration is an error; failed sources never fall back to another
  identity. Legacy `MOTIVEIQ_*` workload aliases remain supported.
- `--role` overrides the role for an API command. Profile `sts_endpoint`
  defaults to `api.motiveiq.net:443`.
- A `file` source uses `type = "file"` and `config.path` pointing to an absolute
  raw-token path. A `process` source uses `config.command`, an argument array
  with an absolute executable or a name on `PATH`, and optional
  `config.login_command`. Relative executable paths are rejected.
- Token processes run without a shell or interactive input and return
  `{"version":1,"token":"OIDC_TOKEN","expires_at":"2030-01-01T00:00:00Z"}`.
  Expiration is optional RFC 3339 metadata. Helpers own token refresh; output
  is limited to 1 MiB and execution to 30 seconds or the caller's shorter
  deadline. Token retrieval never invokes `login_command`.
- OIDC caches use private permissions under `$XDG_CACHE_HOME/iq/oidc/`
  (default `~/.cache/iq/oidc/`). An absolute `token_file` overrides the cache
  location. `authorization_params` supplies provider-specific parameters;
  reserved flow parameters cannot be overridden.
- `iq-oidc access-token SOURCE` serves explicit OAuth access-token consumers.
  Optional `access_token_export_file` writes a process locator for them, with
  relative paths rooted in `XDG_CONFIG_HOME`. Neither is needed for IAM.

## Build and test

```sh
bazel test //...
```

Generated protobuf clients are included, so ordinary Go builds also work:

```sh
go test ./...
go install ./cmd/iq
go build -o iq-oidc ./cmd/iq/oidc
```

For a Go-only installation of the API CLI, use
`go install go.motiveiq.dev/cmd/iq@latest`. It does not install the separate
browser helper; use the Bazel bootstrap above to install both together.

API schemas and clients are under `platform/{iam,s3,kms,secretsmanager}/api/v1`.
Server implementations and the private policy-decision API are not included.
