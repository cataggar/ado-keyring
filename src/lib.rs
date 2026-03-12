use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use pyo3::exceptions::PyRuntimeError;
use pyo3::prelude::*;
use rand::Rng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

// Azure CLI public client — works for Azure DevOps token acquisition
const CLIENT_ID: &str = "04b07795-8ddb-461a-bbee-02f9e1bf7b46";
// Azure DevOps resource ID in Microsoft Entra ID, requesting default permissions and a refresh token
const SCOPE: &str = "499b84ac-1321-427f-aa17-267ca6975798/.default offline_access";
const AUTH_URL: &str = "https://login.microsoftonline.com/organizations/oauth2/v2.0/authorize";
const TOKEN_URL: &str = "https://login.microsoftonline.com/organizations/oauth2/v2.0/token";

// ── Token response types ────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct TokenResponse {
    access_token: String,
    refresh_token: Option<String>,
    expires_in: u64,
}

#[derive(Debug, Deserialize)]
struct SessionTokenResponse {
    token: String,
}

// ── Token cache ─────────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize)]
struct CachedToken {
    access_token: String,
    refresh_token: Option<String>,
    expires_at: u64,
    session_tokens: HashMap<String, CachedSessionToken>,
}

#[derive(Debug, Serialize, Deserialize)]
struct CachedSessionToken {
    token: String,
    expires_at: u64,
}

fn cache_path() -> PathBuf {
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".devops-keyring")
        .join("token-cache.json")
}

fn load_cache() -> Option<CachedToken> {
    let data = std::fs::read_to_string(cache_path()).ok()?;
    serde_json::from_str(&data).ok()
}

fn save_cache(cache: &CachedToken) {
    if let Some(parent) = cache_path().parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let _ = std::fs::write(
        cache_path(),
        serde_json::to_string_pretty(cache).unwrap_or_default(),
    );
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

// ── URL helpers ─────────────────────────────────────────────────────────────

/// Extract the Azure DevOps org name from a feed URL.
fn extract_org(service_url: &str) -> Option<String> {
    let u = url::Url::parse(service_url).ok()?;
    let host = u.host_str()?;

    if host.contains("pkgs.visualstudio.com") || host.contains(".visualstudio.com") {
        Some(host.split('.').next()?.to_string())
    } else if host.contains("dev.azure.com") {
        u.path_segments()?.next().map(|s| s.to_string())
    } else {
        None
    }
}

/// Returns true if the service URL looks like an Azure DevOps package feed.
fn is_devops_url(service_url: &str) -> bool {
    service_url.contains("visualstudio.com") || service_url.contains("dev.azure.com")
}

// ── PKCE ────────────────────────────────────────────────────────────────────

fn generate_pkce() -> (String, String) {
    let mut rng = rand::thread_rng();
    let bytes: [u8; 32] = rng.gen();
    let verifier = URL_SAFE_NO_PAD.encode(bytes);
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    (verifier, challenge)
}

// ── Browser opening (WSL-aware) ─────────────────────────────────────────────

fn is_wsl() -> bool {
    std::fs::read_to_string("/proc/version")
        .map(|v| v.to_lowercase().contains("microsoft"))
        .unwrap_or(false)
}

fn open_browser(url: &str) -> Result<(), String> {
    use std::process::{Command, Stdio};

    // On WSL, use powershell.exe or cmd.exe to open on the Windows side
    let attempts: Vec<(&str, Vec<String>)> = if is_wsl() {
        vec![
            (
                "/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe",
                vec!["-NoProfile".into(), "-Command".into(), format!("Start-Process '{url}'")],
            ),
            (
                "/mnt/c/Windows/system32/cmd.exe",
                vec!["/c".into(), "start".into(), String::new(), url.into()],
            ),
        ]
    } else {
        vec![
            ("xdg-open", vec![url.into()]),
            ("open", vec![url.into()]),
        ]
    };

    for (cmd, args) in &attempts {
        match Command::new(cmd)
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
        {
            Ok(status) if status.success() => return Ok(()),
            _ => continue,
        }
    }

    Err(format!(
        "Could not open browser.\nPlease open this URL manually:\n{url}"
    ))
}

// ── OAuth2 browser auth flow ────────────────────────────────────────────────

fn browser_auth() -> Result<TokenResponse, String> {
    let (verifier, challenge) = generate_pkce();
    let state = URL_SAFE_NO_PAD.encode(rand::thread_rng().gen::<[u8; 16]>());

    // Bind to a random port for the OAuth callback
    let listener = TcpListener::bind("127.0.0.1:0").map_err(|e| format!("bind: {e}"))?;
    let port = listener.local_addr().map_err(|e| format!("addr: {e}"))?.port();
    let redirect_uri = format!("http://localhost:{port}");

    let auth_url = format!(
        "{AUTH_URL}?client_id={CLIENT_ID}\
         &response_type=code\
         &redirect_uri={redirect}\
         &scope={scope}\
         &code_challenge={challenge}\
         &code_challenge_method=S256\
         &state={state}\
         &prompt=select_account",
        redirect = urlencoding::encode(&redirect_uri),
        scope = urlencoding::encode(SCOPE),
    );

    eprintln!("[devops-keyring] Opening browser for Azure DevOps authentication...");
    open_browser(&auth_url)?;

    // Wait for the OAuth callback
    let (mut stream, _) = listener.accept().map_err(|e| format!("accept: {e}"))?;
    let mut buf = vec![0u8; 8192];
    let n = stream.read(&mut buf).map_err(|e| format!("read: {e}"))?;
    let request = String::from_utf8_lossy(&buf[..n]);

    // Parse the callback URL
    let path = request
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .ok_or("invalid HTTP request on callback")?;

    let callback =
        url::Url::parse(&format!("http://localhost{path}")).map_err(|e| format!("parse: {e}"))?;
    let params: HashMap<String, String> = callback
        .query_pairs()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();

    // Check for errors
    if let Some(err) = params.get("error") {
        let desc = params.get("error_description").cloned().unwrap_or_default();
        send_html(&mut stream, "Authentication Failed", "An error occurred. You can close this tab.");
        return Err(format!("{err}: {desc}"));
    }

    let code = params.get("code").ok_or("missing 'code' in callback")?;

    // Verify state
    if params.get("state").map(|s| s.as_str()) != Some(&state) {
        send_html(&mut stream, "Error", "State mismatch — possible CSRF.");
        return Err("OAuth state mismatch".into());
    }

    send_html(
        &mut stream,
        "Authentication Successful",
        "You can close this tab and return to the terminal.",
    );
    drop(stream);

    // Exchange authorization code for tokens
    exchange_code(code, &redirect_uri, &verifier)
}

fn send_html(stream: &mut impl Write, title: &str, body: &str) {
    let html = format!(
        "<html><head><title>{title}</title></head>\
         <body style=\"font-family:sans-serif;text-align:center;margin-top:80px\">\
         <h1>{title}</h1><p>{body}</p></body></html>"
    );
    let resp = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        html.len(),
        html
    );
    let _ = stream.write_all(resp.as_bytes());
    let _ = stream.flush();
}

fn exchange_code(code: &str, redirect_uri: &str, verifier: &str) -> Result<TokenResponse, String> {
    let client = reqwest::blocking::Client::new();
    let resp = client
        .post(TOKEN_URL)
        .form(&[
            ("client_id", CLIENT_ID),
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", redirect_uri),
            ("code_verifier", verifier),
        ])
        .send()
        .map_err(|e| format!("token request failed: {e}"))?;

    if !resp.status().is_success() {
        let body = resp.text().unwrap_or_default();
        return Err(format!("token exchange failed ({}): {body}", body.len()));
    }

    resp.json::<TokenResponse>()
        .map_err(|e| format!("parse token response: {e}"))
}

// ── Token refresh ───────────────────────────────────────────────────────────

fn refresh_access_token(refresh_token: &str) -> Result<TokenResponse, String> {
    let client = reqwest::blocking::Client::new();
    let resp = client
        .post(TOKEN_URL)
        .form(&[
            ("client_id", CLIENT_ID),
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh_token),
            ("scope", SCOPE),
        ])
        .send()
        .map_err(|e| format!("refresh request: {e}"))?;

    if !resp.status().is_success() {
        return Err("refresh token expired or revoked".into());
    }

    resp.json::<TokenResponse>()
        .map_err(|e| format!("parse refresh response: {e}"))
}

// ── VssSessionToken exchange ────────────────────────────────────────────────

fn get_session_token(access_token: &str, org: &str) -> Result<String, String> {
    let url = format!(
        "https://vssps.dev.azure.com/{org}/_apis/token/sessiontokens?api-version=5.0-preview.1"
    );
    let client = reqwest::blocking::Client::new();
    let resp = client
        .post(&url)
        .header("Authorization", format!("Bearer {access_token}"))
        .json(&serde_json::json!({"scope": "vso.packaging", "targetAccounts": []}))
        .send()
        .map_err(|e| format!("session token request: {e}"))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().unwrap_or_default();
        return Err(format!("session token failed ({status}): {body}"));
    }

    let data: SessionTokenResponse = resp
        .json()
        .map_err(|e| format!("parse session token: {e}"))?;
    Ok(data.token)
}

// ── Main entry point ────────────────────────────────────────────────────────

fn do_authenticate(service_url: &str) -> Result<Option<(String, String)>, String> {
    if !is_devops_url(service_url) {
        return Ok(None);
    }

    let org = extract_org(service_url).ok_or_else(|| {
        format!("could not extract Azure DevOps org from URL: {service_url}")
    })?;

    let now = now_secs();
    let mut cache = load_cache();

    // 1. Check cached session token (valid with 5-min buffer)
    if let Some(ref c) = cache {
        if let Some(st) = c.session_tokens.get(&org) {
            if st.expires_at > now + 300 {
                eprintln!("[devops-keyring] Using cached session token for '{org}'");
                return Ok(Some(("VssSessionToken".into(), st.token.clone())));
            }
        }
    }

    // 2. Get a valid access token (refresh or browser)
    let token_resp = match cache {
        Some(ref c) if c.expires_at > now + 60 => {
            // Access token is still valid
            None
        }
        Some(ref c) if c.refresh_token.is_some() => {
            let rt = c.refresh_token.as_ref().unwrap();
            eprintln!("[devops-keyring] Refreshing access token...");
            match refresh_access_token(rt) {
                Ok(tr) => Some(tr),
                Err(e) => {
                    eprintln!("[devops-keyring] Refresh failed ({e}), falling back to browser");
                    Some(browser_auth()?)
                }
            }
        }
        _ => {
            eprintln!("[devops-keyring] No cached token, starting browser auth...");
            Some(browser_auth()?)
        }
    };

    // Update cache with fresh access token
    if let Some(tr) = token_resp {
        let prev_sessions = cache.map(|c| c.session_tokens).unwrap_or_default();
        cache = Some(CachedToken {
            access_token: tr.access_token,
            refresh_token: tr.refresh_token,
            expires_at: now + tr.expires_in,
            session_tokens: prev_sessions,
        });
    }

    let mut cache = cache.expect("cache must exist at this point");

    // 3. Exchange for VssSessionToken
    eprintln!("[devops-keyring] Exchanging for VssSessionToken ({org})...");
    let session_token = get_session_token(&cache.access_token, &org)?;

    // Cache session token (~50 min lifetime)
    cache.session_tokens.insert(
        org.clone(),
        CachedSessionToken {
            token: session_token.clone(),
            expires_at: now + 3000,
        },
    );
    save_cache(&cache);

    eprintln!("[devops-keyring] ✓ Authenticated to '{org}'");
    Ok(Some(("VssSessionToken".into(), session_token)))
}

// ── PyO3 module ─────────────────────────────────────────────────────────────

#[pyfunction]
fn authenticate(py: Python, service_url: String) -> PyResult<Option<(String, String)>> {
    py.allow_threads(|| do_authenticate(&service_url))
        .map_err(|e| PyRuntimeError::new_err(e))
}

#[pymodule]
fn _native(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(authenticate, m)?)?;
    Ok(())
}
