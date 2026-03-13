# ado-keyring

A [keyring](https://pypi.org/project/keyring/) backend in pure python that authenticates to Azure DevOps package feeds using browser-based OAuth2 with PKCE.

Once installed, keyring automatically discovers `ado-keyring` as a backend. Any tool that uses keyring, such as [`uv`](https://docs.astral.sh/uv/) for [alternative indexes](https://docs.astral.sh/uv/guides/integration/alternative-indexes/), will trigger browser auth when accessing Azure DevOps feeds.

## Install from PyPi

```sh
uv tool install keyring --with ado-keyring
```

## Features

- **Browser-based OAuth2 + PKCE** — secure, no secrets stored in config files
- **Persistent token cache** — avoids repeated browser prompts (`~/.ado-keyring/`)
- **Automatic token refresh** — uses refresh tokens to silently renew access
- **Per-org session tokens** — supports multiple Azure DevOps organizations
- **WSL-aware** — opens the Windows browser from WSL via `cmd.exe`
- **No .NET dependency** — pure Python, unlike [`artifacts-keyring`](https://github.com/microsoft/artifacts-keyring)

## Install from source

```sh
just install
```

## Install on WSL from source

```sh
tdnf install -y python3 python3-pip
python3 -m pip install
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc && source ~/.bashrc
uv tool install rust-just
just install
```

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
