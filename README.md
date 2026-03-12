# ado-keyring

A [keyring](https://pypi.org/project/keyring/) backend that authenticates to Azure DevOps package feeds using browser-based OAuth2 with PKCE.

Built for environments where the .NET credential provider doesn't work — particularly **WSL**.

## Features

- **Browser-based OAuth2 + PKCE** — secure, no secrets stored in config files
- **Persistent token cache** — avoids repeated browser prompts (`~/.ado-keyring/`)
- **Automatic token refresh** — uses refresh tokens to silently renew access
- **Per-org session tokens** — supports multiple Azure DevOps organizations
- **WSL-aware** — opens the Windows browser from WSL via PowerShell or `cmd.exe`
- **No .NET dependency** — pure Python, unlike [`artifacts-keyring`](https://github.com/microsoft/artifacts-keyring)

## Supported Hosts

- `*.visualstudio.com`
- `dev.azure.com`
- `pkgs.codedev.ms`
- `pkgs.vsts.me`

## Install

```sh
uv tool install keyring --with ado-keyring
```

Or from a local build:

```sh
uv build
uv tool install keyring --with dist/ado_keyring-0.1.0-py3-none-any.whl
```

## Usage

Once installed, keyring automatically discovers `ado-keyring` as a backend. Any tool that uses keyring, such as [`uv`](https://docs.astral.sh/uv/) for [alternative indexes](https://docs.astral.sh/uv/guides/integration/alternative-indexes/), will trigger browser auth when accessing Azure DevOps feeds.

## How It Works

1. Binds a localhost callback server on a random port
2. Opens the browser to Azure AD's OAuth2 authorize endpoint (PKCE, `select_account` prompt)
3. Receives the authorization code via redirect
4. Exchanges the code for access + refresh tokens
5. Exchanges the access token for a `VssSessionToken` scoped to `vso.packaging`
6. Caches all tokens to `~/.ado-keyring/token-cache.json` (file: `0600`, dir: `0700`)
7. On subsequent calls, uses cached session tokens or silently refreshes via the refresh token

## License

[MIT](LICENSE)
