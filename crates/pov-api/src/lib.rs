//! POV Story local HTTP surface.

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
#[cfg(unix)]
use std::{
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use axum::{
    Router,
    body::Body,
    http::{Method, StatusCode, Uri, header},
    response::{IntoResponse, Response},
    routing::get,
};
#[cfg(unix)]
use axum::{
    body::Bytes,
    extract::{DefaultBodyLimit, State},
    http::{HeaderMap, HeaderName, HeaderValue},
    routing::post,
};
#[cfg(unix)]
use pov_core::auth::{
    AuthProfile, AuthRuntime, CredentialMutationOutcome, IssuedSession, LoginOutcome, LoginRequest,
    LogoutAllOutcome, LogoutOutcome, NormalizedPassword, RefreshOutcome, SecretBytes,
};
use rust_embed::Embed;
#[cfg(unix)]
use serde::{
    Deserialize, Deserializer,
    de::{self, MapAccess, Visitor},
};

pub const DEFAULT_BIND_ADDRESS: SocketAddr =
    SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 8080));

const CONTENT_SECURITY_POLICY: &str = concat!(
    "default-src 'self'; script-src 'self'; style-src 'self'; ",
    "connect-src 'self'; img-src 'self' data:; font-src 'self'; ",
    "object-src 'none'; base-uri 'none'; frame-ancestors 'none'"
);

#[derive(Embed)]
#[folder = "../../web/dist/"]
struct WebAssets;

#[cfg(unix)]
const MAX_AUTH_REQUEST_BYTES: usize = 4096;
#[cfg(unix)]
const LOCAL_ORIGIN: &str = "http://127.0.0.1:8080";
#[cfg(unix)]
const LOCAL_HOST: &str = "127.0.0.1:8080";
#[cfg(unix)]
const LOCAL_REFRESH_COOKIE: &str = "pov_refresh_local";
#[cfg(unix)]
const LOCAL_REFRESH_COOKIE_PATH: &str = "/api/auth";
#[cfg(unix)]
const CSRF_HEADER: HeaderName = HeaderName::from_static("x-pov-csrf");
#[cfg(unix)]
const FETCH_SITE_HEADER: HeaderName = HeaderName::from_static("sec-fetch-site");

pub fn app() -> Router {
    let api = Router::new()
        .route("/health", get(health))
        .fallback(api_not_found);

    Router::new().nest("/api", api).fallback(serve_web_asset)
}

#[cfg(unix)]
#[derive(Clone)]
struct AuthApiState {
    runtime: Arc<AuthRuntime>,
}

#[cfg(unix)]
pub fn app_with_auth(runtime: Arc<AuthRuntime>) -> Router {
    let auth = Router::new()
        .route("/login", post(login))
        .route("/refresh", post(refresh))
        .route("/logout", post(logout))
        .route("/logout-all", post(logout_all))
        .route("/password", post(change_password))
        .route("/session", get(session_status))
        .layer(DefaultBodyLimit::max(MAX_AUTH_REQUEST_BYTES))
        .with_state(AuthApiState { runtime });
    let api = Router::new()
        .route("/health", get(health))
        .nest("/auth", auth)
        .fallback(api_not_found);

    Router::new().nest("/api", api).fallback(serve_web_asset)
}

#[cfg(unix)]
struct LoginPayload {
    login_attempt_id: String,
    login_id: String,
    password: String,
}

#[cfg(unix)]
struct EmptyPayload {}

#[cfg(unix)]
struct PasswordChangePayload {
    current_password: String,
    new_password: String,
}

#[cfg(unix)]
impl<'de> Deserialize<'de> for LoginPayload {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct LoginVisitor;

        impl<'de> Visitor<'de> for LoginVisitor {
            type Value = LoginPayload;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("an exact local login object")
            }

            fn visit_map<M>(self, mut map: M) -> Result<Self::Value, M::Error>
            where
                M: MapAccess<'de>,
            {
                let mut attempt = None;
                let mut login = None;
                let mut password = None;
                while let Some(field) = map.next_key::<String>()? {
                    match field.as_str() {
                        "login_attempt_id" if attempt.is_none() => {
                            attempt = Some(map.next_value()?);
                        }
                        "login_id" if login.is_none() => {
                            login = Some(map.next_value()?);
                        }
                        "password" if password.is_none() => {
                            password = Some(map.next_value()?);
                        }
                        "login_attempt_id" | "login_id" | "password" => {
                            return Err(de::Error::duplicate_field("authentication field"));
                        }
                        _ => return Err(de::Error::unknown_field("authentication field", &[])),
                    }
                }
                Ok(LoginPayload {
                    login_attempt_id: attempt
                        .ok_or_else(|| de::Error::missing_field("login_attempt_id"))?,
                    login_id: login.ok_or_else(|| de::Error::missing_field("login_id"))?,
                    password: password.ok_or_else(|| de::Error::missing_field("password"))?,
                })
            }
        }

        deserializer.deserialize_map(LoginVisitor)
    }
}

#[cfg(unix)]
impl<'de> Deserialize<'de> for EmptyPayload {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct EmptyVisitor;

        impl<'de> Visitor<'de> for EmptyVisitor {
            type Value = EmptyPayload;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("an empty object")
            }

            fn visit_map<M>(self, mut map: M) -> Result<Self::Value, M::Error>
            where
                M: MapAccess<'de>,
            {
                if map.next_key::<String>()?.is_some() {
                    return Err(de::Error::unknown_field("authentication field", &[]));
                }
                Ok(EmptyPayload {})
            }
        }

        deserializer.deserialize_map(EmptyVisitor)
    }
}

#[cfg(unix)]
impl<'de> Deserialize<'de> for PasswordChangePayload {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct PasswordChangeVisitor;

        impl<'de> Visitor<'de> for PasswordChangeVisitor {
            type Value = PasswordChangePayload;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("an exact password change object")
            }

            fn visit_map<M>(self, mut map: M) -> Result<Self::Value, M::Error>
            where
                M: MapAccess<'de>,
            {
                let mut current = None;
                let mut new = None;
                while let Some(field) = map.next_key::<String>()? {
                    match field.as_str() {
                        "current_password" if current.is_none() => {
                            current = Some(map.next_value()?);
                        }
                        "new_password" if new.is_none() => {
                            new = Some(map.next_value()?);
                        }
                        "current_password" | "new_password" => {
                            return Err(de::Error::duplicate_field("password field"));
                        }
                        _ => return Err(de::Error::unknown_field("password field", &[])),
                    }
                }
                Ok(PasswordChangePayload {
                    current_password: current
                        .ok_or_else(|| de::Error::missing_field("current_password"))?,
                    new_password: new.ok_or_else(|| de::Error::missing_field("new_password"))?,
                })
            }
        }

        deserializer.deserialize_map(PasswordChangeVisitor)
    }
}

#[cfg(unix)]
async fn login(State(state): State<AuthApiState>, headers: HeaderMap, body: Bytes) -> Response {
    if !valid_mutation_headers(&headers) {
        return auth_error(StatusCode::FORBIDDEN, "request_rejected");
    }
    let payload: LoginPayload = match serde_json::from_slice(&body) {
        Ok(payload) => payload,
        Err(_) => return auth_error(StatusCode::BAD_REQUEST, "invalid_request"),
    };
    let attempt_id = match payload.login_attempt_id.parse() {
        Ok(attempt_id) => attempt_id,
        Err(_) => return auth_error(StatusCode::BAD_REQUEST, "invalid_request"),
    };
    let password = match NormalizedPassword::parse(SecretBytes::new(payload.password.into_bytes()))
    {
        Ok(password) => password,
        Err(_) => return auth_error(StatusCode::BAD_REQUEST, "invalid_request"),
    };
    let request = match LoginRequest::local(attempt_id, payload.login_id, password) {
        Ok(request) => request,
        Err(_) => return auth_error(StatusCode::BAD_REQUEST, "invalid_request"),
    };
    let now_micros = match current_time_micros() {
        Some(now) => now,
        None => {
            return auth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "authentication_unavailable",
            );
        }
    };
    match state.runtime.login(request, now_micros).await {
        Ok(LoginOutcome::Authenticated(session)) => auth_session_response(session, now_micros),
        Ok(LoginOutcome::GenericFailure) => {
            auth_error(StatusCode::UNAUTHORIZED, "invalid_credentials")
        }
        Ok(LoginOutcome::Throttled) => {
            auth_error(StatusCode::TOO_MANY_REQUESTS, "authentication_unavailable")
        }
        Ok(LoginOutcome::OutcomeUnknown) => {
            auth_error(StatusCode::CONFLICT, "login_outcome_unknown")
        }
        Ok(LoginOutcome::AttemptInvalidated) => {
            auth_error(StatusCode::CONFLICT, "login_attempt_invalidated")
        }
        Ok(LoginOutcome::RetryRequired) => auth_error(StatusCode::CONFLICT, "login_retry_required"),
        Err(_) => auth_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "authentication_unavailable",
        ),
    }
}

#[cfg(unix)]
async fn refresh(State(state): State<AuthApiState>, headers: HeaderMap, body: Bytes) -> Response {
    if !valid_mutation_headers(&headers) || serde_json::from_slice::<EmptyPayload>(&body).is_err() {
        return auth_error(StatusCode::FORBIDDEN, "request_rejected");
    }
    let cookie = match local_refresh_cookie(&headers) {
        Ok(Some(cookie)) => SecretBytes::new(cookie.into_bytes()),
        Ok(None) | Err(()) => SecretBytes::new(Vec::new()),
    };
    let now_micros = match current_time_micros() {
        Some(now) => now,
        None => {
            return auth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "authentication_unavailable",
            );
        }
    };
    match state
        .runtime
        .refresh(AuthProfile::Local, cookie, now_micros)
        .await
    {
        Ok(RefreshOutcome::Rotated(session)) => auth_session_response(session, now_micros),
        Ok(RefreshOutcome::ReplayRevoked | RefreshOutcome::Exhausted | RefreshOutcome::Invalid) => {
            auth_error_with_clear_cookie(StatusCode::UNAUTHORIZED, "invalid_session")
        }
        Err(_) => auth_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "authentication_unavailable",
        ),
    }
}

#[cfg(unix)]
async fn logout(State(state): State<AuthApiState>, headers: HeaderMap, body: Bytes) -> Response {
    if !valid_mutation_headers(&headers) || serde_json::from_slice::<EmptyPayload>(&body).is_err() {
        return auth_error(StatusCode::FORBIDDEN, "request_rejected");
    }
    let cookie = match local_refresh_cookie(&headers) {
        Ok(Some(cookie)) => Some(SecretBytes::new(cookie.into_bytes())),
        Ok(None) | Err(()) => None,
    };
    let now_micros = match current_time_micros() {
        Some(now) => now,
        None => {
            return auth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "authentication_unavailable",
            );
        }
    };
    match state
        .runtime
        .logout(AuthProfile::Local, cookie, now_micros)
        .await
    {
        Ok(LogoutOutcome::Revoked | LogoutOutcome::AlreadyTerminal) => {
            auth_error_with_clear_cookie(StatusCode::OK, "logged_out")
        }
        Err(_) => auth_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "authentication_unavailable",
        ),
    }
}

#[cfg(unix)]
async fn logout_all(
    State(state): State<AuthApiState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if !valid_mutation_headers(&headers) || serde_json::from_slice::<EmptyPayload>(&body).is_err() {
        return auth_error(StatusCode::FORBIDDEN, "request_rejected");
    }
    let Some(access) = bearer_token(&headers) else {
        return auth_error(StatusCode::UNAUTHORIZED, "invalid_token");
    };
    let now_micros = match current_time_micros() {
        Some(now) => now,
        None => {
            return auth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "authentication_unavailable",
            );
        }
    };
    match state
        .runtime
        .logout_all(SecretBytes::new(access.into_bytes()), now_micros)
        .await
    {
        Ok(LogoutAllOutcome::Revoked) => {
            auth_status_with_clear_cookie(StatusCode::OK, "logged_out_all")
        }
        Ok(LogoutAllOutcome::InvalidSession) => {
            auth_error(StatusCode::UNAUTHORIZED, "invalid_token")
        }
        Err(_) => auth_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "authentication_unavailable",
        ),
    }
}

#[cfg(unix)]
async fn change_password(
    State(state): State<AuthApiState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if !valid_mutation_headers(&headers) {
        return auth_error(StatusCode::FORBIDDEN, "request_rejected");
    }
    let Some(access) = bearer_token(&headers) else {
        return auth_error(StatusCode::UNAUTHORIZED, "invalid_token");
    };
    let payload: PasswordChangePayload = match serde_json::from_slice(&body) {
        Ok(payload) => payload,
        Err(_) => return auth_error(StatusCode::BAD_REQUEST, "invalid_request"),
    };
    let current =
        match NormalizedPassword::parse(SecretBytes::new(payload.current_password.into_bytes())) {
            Ok(password) => password,
            Err(_) => return auth_error(StatusCode::BAD_REQUEST, "invalid_request"),
        };
    let new = match NormalizedPassword::parse(SecretBytes::new(payload.new_password.into_bytes())) {
        Ok(password) => password,
        Err(_) => return auth_error(StatusCode::BAD_REQUEST, "invalid_request"),
    };
    let now_micros = match current_time_micros() {
        Some(now) => now,
        None => {
            return auth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "authentication_unavailable",
            );
        }
    };
    match state
        .runtime
        .change_password(
            SecretBytes::new(access.into_bytes()),
            current,
            new,
            now_micros,
        )
        .await
    {
        Ok(CredentialMutationOutcome::Changed) => {
            auth_status_with_clear_cookie(StatusCode::OK, "password_changed")
        }
        Ok(CredentialMutationOutcome::GenericFailure) => {
            auth_error(StatusCode::UNAUTHORIZED, "invalid_credentials")
        }
        Ok(CredentialMutationOutcome::Throttled) => {
            auth_error(StatusCode::TOO_MANY_REQUESTS, "authentication_unavailable")
        }
        Ok(CredentialMutationOutcome::RetryRequired) => {
            auth_error(StatusCode::CONFLICT, "credential_retry_required")
        }
        Ok(CredentialMutationOutcome::InvalidSession) => {
            auth_error(StatusCode::UNAUTHORIZED, "invalid_token")
        }
        Ok(CredentialMutationOutcome::AlreadyApplied) => {
            auth_status_with_clear_cookie(StatusCode::OK, "password_changed")
        }
        Err(_) => auth_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "authentication_unavailable",
        ),
    }
}

#[cfg(unix)]
async fn session_status(State(state): State<AuthApiState>, headers: HeaderMap) -> Response {
    if !valid_local_host(&headers) {
        return auth_error(StatusCode::FORBIDDEN, "request_rejected");
    }
    let Some(token) = bearer_token(&headers) else {
        return auth_error(StatusCode::UNAUTHORIZED, "invalid_token");
    };
    let now_micros = match current_time_micros() {
        Some(now) => now,
        None => {
            return auth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "authentication_unavailable",
            );
        }
    };
    match state
        .runtime
        .verify_access(
            AuthProfile::Local,
            SecretBytes::new(token.into_bytes()),
            now_micros,
        )
        .await
    {
        Ok(_) => auth_json(
            StatusCode::OK,
            serde_json::json!({"authenticated": true}),
            None,
        ),
        Err(_) => auth_error(StatusCode::UNAUTHORIZED, "invalid_token"),
    }
}

#[cfg(unix)]
fn valid_mutation_headers(headers: &HeaderMap) -> bool {
    valid_local_host(headers)
        && exact_single_header(headers, header::ORIGIN).is_some_and(|value| value == LOCAL_ORIGIN)
        && exact_single_header(headers, CSRF_HEADER).is_some_and(|value| value == "1")
        && exact_single_header(headers, header::CONTENT_TYPE).is_some_and(valid_json_content_type)
        && match exact_optional_header(headers, FETCH_SITE_HEADER) {
            Ok(None) => true,
            Ok(Some(value)) => value == "same-origin",
            Err(()) => false,
        }
}

#[cfg(unix)]
fn valid_local_host(headers: &HeaderMap) -> bool {
    exact_single_header(headers, header::HOST).is_some_and(|value| value == LOCAL_HOST)
}

#[cfg(unix)]
fn valid_json_content_type(value: &str) -> bool {
    matches!(
        value,
        "application/json" | "application/json; charset=utf-8"
    )
}

#[cfg(unix)]
fn exact_single_header(headers: &HeaderMap, name: HeaderName) -> Option<&str> {
    let mut values = headers.get_all(name).iter();
    let first = values.next()?.to_str().ok()?;
    if values.next().is_some() {
        return None;
    }
    Some(first)
}

#[cfg(unix)]
fn exact_optional_header(headers: &HeaderMap, name: HeaderName) -> Result<Option<&str>, ()> {
    let mut values = headers.get_all(name).iter();
    let Some(first) = values.next() else {
        return Ok(None);
    };
    let first = first.to_str().map_err(|_| ())?;
    if values.next().is_some() {
        return Err(());
    }
    Ok(Some(first))
}

#[cfg(unix)]
fn local_refresh_cookie(headers: &HeaderMap) -> Result<Option<String>, ()> {
    let Some(raw) = exact_optional_header(headers, header::COOKIE)? else {
        return Ok(None);
    };
    let mut selected = None;
    for pair in raw.split(';') {
        let pair = pair.trim_matches([' ', '\t']);
        let (name, value) = pair.split_once('=').ok_or(())?;
        if name.is_empty()
            || value.is_empty()
            || name.bytes().any(|byte| !is_cookie_name_byte(byte))
            || value
                .bytes()
                .any(|byte| !byte.is_ascii() || byte.is_ascii_control() || byte == b';')
        {
            return Err(());
        }
        if name == LOCAL_REFRESH_COOKIE {
            if selected.is_some() {
                return Err(());
            }
            selected = Some(value.to_owned());
        }
    }
    Ok(selected)
}

#[cfg(unix)]
const fn is_cookie_name_byte(byte: u8) -> bool {
    matches!(
        byte,
        b'a'..=b'z'
            | b'A'..=b'Z'
            | b'0'..=b'9'
            | b'!'
            | b'#'
            | b'$'
            | b'%'
            | b'&'
            | b'\''
            | b'*'
            | b'+'
            | b'-'
            | b'.'
            | b'^'
            | b'_'
            | b'`'
            | b'|'
            | b'~'
    )
}

#[cfg(unix)]
fn bearer_token(headers: &HeaderMap) -> Option<String> {
    let value = exact_single_header(headers, header::AUTHORIZATION)?;
    let token = value.strip_prefix("Bearer ")?;
    if token.is_empty()
        || token
            .bytes()
            .any(|byte| !byte.is_ascii() || byte.is_ascii_whitespace())
    {
        return None;
    }
    Some(token.to_owned())
}

#[cfg(unix)]
fn auth_session_response(session: IssuedSession, now_micros: u64) -> Response {
    let cookie = local_issue_cookie(
        session.refresh_token(),
        session.refresh_expires_at_seconds(),
        now_micros,
    );
    auth_json(
        StatusCode::OK,
        serde_json::json!({
            "access_token": session.access_token(),
            "token_type": "Bearer",
            "expires_at": session.access_expires_at_seconds(),
        }),
        HeaderValue::from_str(&cookie).ok(),
    )
}

#[cfg(unix)]
fn local_issue_cookie(
    refresh_token: &str,
    refresh_expires_at_seconds: u64,
    now_micros: u64,
) -> String {
    let max_age = refresh_expires_at_seconds.saturating_sub(now_micros / 1_000_000);
    format!(
        "{LOCAL_REFRESH_COOKIE}={refresh_token}; Path={LOCAL_REFRESH_COOKIE_PATH}; HttpOnly; SameSite=Strict; Max-Age={max_age}"
    )
}

#[cfg(unix)]
fn auth_error(status: StatusCode, error: &'static str) -> Response {
    auth_json(status, serde_json::json!({"error": error}), None)
}

#[cfg(unix)]
fn auth_error_with_clear_cookie(status: StatusCode, error: &'static str) -> Response {
    let cookie = format!(
        "{LOCAL_REFRESH_COOKIE}=; Path={LOCAL_REFRESH_COOKIE_PATH}; HttpOnly; SameSite=Strict; Max-Age=0"
    );
    auth_json(
        status,
        serde_json::json!({"error": error}),
        HeaderValue::from_str(&cookie).ok(),
    )
}

#[cfg(unix)]
fn auth_status_with_clear_cookie(status: StatusCode, value: &'static str) -> Response {
    let cookie = format!(
        "{LOCAL_REFRESH_COOKIE}=; Path={LOCAL_REFRESH_COOKIE_PATH}; HttpOnly; SameSite=Strict; Max-Age=0"
    );
    auth_json(
        status,
        serde_json::json!({"status": value}),
        HeaderValue::from_str(&cookie).ok(),
    )
}

#[cfg(unix)]
fn auth_json(
    status: StatusCode,
    payload: serde_json::Value,
    set_cookie: Option<HeaderValue>,
) -> Response {
    let body = match serde_json::to_vec(&payload) {
        Ok(body) => body,
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };
    let mut response = Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/json; charset=utf-8")
        .header(header::CACHE_CONTROL, "no-store")
        .header(header::PRAGMA, "no-cache")
        .header(header::REFERRER_POLICY, "no-referrer");
    if let Some(cookie) = set_cookie {
        response = response.header(header::SET_COOKIE, cookie);
    }
    response
        .body(Body::from(body))
        .expect("auth response headers are valid")
}

#[cfg(unix)]
fn current_time_micros() -> Option<u64> {
    let micros = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()?
        .as_micros();
    u64::try_from(micros).ok()
}

async fn health() -> impl IntoResponse {
    (
        [
            (header::CONTENT_TYPE, "application/json; charset=utf-8"),
            (header::CACHE_CONTROL, "no-store"),
        ],
        r#"{"status":"ok"}"#,
    )
}

async fn api_not_found() -> StatusCode {
    StatusCode::NOT_FOUND
}

async fn serve_web_asset(method: Method, uri: Uri) -> Response {
    if method != Method::GET && method != Method::HEAD {
        return Response::builder()
            .status(StatusCode::METHOD_NOT_ALLOWED)
            .header(header::ALLOW, "GET, HEAD")
            .body(Body::empty())
            .expect("method response headers are valid");
    }

    let requested_path = uri.path().trim_start_matches('/');

    let response = if requested_path.is_empty() {
        embedded_asset_response("index.html")
    } else if !is_safe_asset_path(requested_path) {
        StatusCode::NOT_FOUND.into_response()
    } else if WebAssets::get(requested_path).is_some() {
        embedded_asset_response(requested_path)
    } else if !requested_path.contains('.') {
        embedded_asset_response("index.html")
    } else {
        StatusCode::NOT_FOUND.into_response()
    };

    if method == Method::HEAD {
        let (parts, _) = response.into_parts();
        Response::from_parts(parts, Body::empty())
    } else {
        response
    }
}

fn is_safe_asset_path(path: &str) -> bool {
    !path.contains(['%', '\\'])
        && path
            .split('/')
            .all(|segment| !matches!(segment, "" | "." | ".."))
}

fn embedded_asset_response(path: &str) -> Response {
    let Some(asset) = WebAssets::get(path) else {
        return StatusCode::NOT_FOUND.into_response();
    };

    let content_type = mime_guess::from_path(path).first_or_octet_stream();
    let data = asset.data.into_owned();
    let content_length = data.len().to_string();

    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, content_type.as_ref())
        .header(header::CONTENT_LENGTH, content_length)
        .header(header::CACHE_CONTROL, "no-store")
        .header(header::CONTENT_SECURITY_POLICY, CONTENT_SECURITY_POLICY)
        .header("x-content-type-options", "nosniff")
        .body(Body::from(data))
        .expect("static response headers are valid")
}

#[cfg(all(test, unix))]
mod auth_http_tests {
    use axum::{
        body::to_bytes,
        http::{HeaderMap, HeaderValue, StatusCode, header},
    };

    use super::{
        CSRF_HEADER, FETCH_SITE_HEADER, LOCAL_HOST, LOCAL_ORIGIN, LoginPayload, auth_error,
        auth_error_with_clear_cookie, bearer_token, local_issue_cookie, local_refresh_cookie,
        valid_mutation_headers,
    };

    fn valid_headers() -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(header::HOST, HeaderValue::from_static(LOCAL_HOST));
        headers.insert(header::ORIGIN, HeaderValue::from_static(LOCAL_ORIGIN));
        headers.insert(CSRF_HEADER, HeaderValue::from_static("1"));
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        headers.insert(FETCH_SITE_HEADER, HeaderValue::from_static("same-origin"));
        headers
    }

    #[test]
    fn csrf_boundary_requires_exact_single_profile_headers() {
        assert!(valid_mutation_headers(&valid_headers()));
        for name in [
            header::HOST,
            header::ORIGIN,
            CSRF_HEADER,
            header::CONTENT_TYPE,
        ] {
            let mut headers = valid_headers();
            headers.remove(name);
            assert!(!valid_mutation_headers(&headers));
        }
        for (name, wrong) in [
            (header::HOST, "localhost:8080"),
            (header::ORIGIN, "null"),
            (CSRF_HEADER, "0"),
            (header::CONTENT_TYPE, "text/plain"),
            (FETCH_SITE_HEADER, "cross-site"),
        ] {
            let mut headers = valid_headers();
            headers.insert(name, HeaderValue::from_static(wrong));
            assert!(!valid_mutation_headers(&headers));
        }
        let mut duplicate = valid_headers();
        duplicate.append(header::ORIGIN, HeaderValue::from_static(LOCAL_ORIGIN));
        assert!(!valid_mutation_headers(&duplicate));
        let mut without_fetch_metadata = valid_headers();
        without_fetch_metadata.remove(FETCH_SITE_HEADER);
        assert!(valid_mutation_headers(&without_fetch_metadata));
    }

    #[test]
    fn login_json_rejects_missing_duplicate_unknown_and_wrong_types() {
        let exact = br#"{
            "password":"correct horse battery staple",
            "login_id":"owner_01",
            "login_attempt_id":"11111111-1111-4111-8111-111111111111"
        }"#;
        assert!(serde_json::from_slice::<LoginPayload>(exact).is_ok());
        for invalid in [
            br#"{"login_id":"owner_01","password":"correct horse battery staple"}"#.as_slice(),
            br#"{"login_attempt_id":"11111111-1111-4111-8111-111111111111","login_id":"owner_01","login_id":"owner_02","password":"correct horse battery staple"}"#.as_slice(),
            br#"{"login_attempt_id":"11111111-1111-4111-8111-111111111111","login_id":"owner_01","password":"correct horse battery staple","owner_id":"33333333-3333-4333-8333-333333333333"}"#.as_slice(),
            br#"{"login_attempt_id":1,"login_id":"owner_01","password":"correct horse battery staple"}"#.as_slice(),
        ] {
            assert!(serde_json::from_slice::<LoginPayload>(invalid).is_err());
        }
    }

    #[test]
    fn refresh_cookie_is_exact_single_host_only_cookie() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            HeaderValue::from_static("theme=dark; pov_refresh_local=opaque_token"),
        );
        assert_eq!(
            local_refresh_cookie(&headers).expect("valid cookies"),
            Some("opaque_token".to_owned())
        );
        headers.insert(
            header::COOKIE,
            HeaderValue::from_static("pov_refresh_local=first; pov_refresh_local=second"),
        );
        assert!(local_refresh_cookie(&headers).is_err());

        let issue = local_issue_cookie("opaque_token", 1_700_000_600, 1_700_000_000_000_000);
        assert_eq!(
            issue,
            "pov_refresh_local=opaque_token; Path=/api/auth; HttpOnly; SameSite=Strict; Max-Age=600"
        );
        assert!(!issue.contains("Secure"));
        assert!(!issue.contains("Domain"));
    }

    #[test]
    fn bearer_header_is_single_exact_and_whitespace_free() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer header.payload.signature"),
        );
        assert_eq!(
            bearer_token(&headers),
            Some("header.payload.signature".to_owned())
        );
        headers.append(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer second"),
        );
        assert!(bearer_token(&headers).is_none());
    }

    #[tokio::test]
    async fn auth_responses_are_no_store_and_clear_exact_cookie() {
        let response = auth_error(StatusCode::UNAUTHORIZED, "invalid_token");
        assert_eq!(
            response.headers().get(header::CACHE_CONTROL),
            Some(&HeaderValue::from_static("no-store"))
        );
        assert_eq!(
            response.headers().get(header::PRAGMA),
            Some(&HeaderValue::from_static("no-cache"))
        );
        assert_eq!(
            response.headers().get(header::REFERRER_POLICY),
            Some(&HeaderValue::from_static("no-referrer"))
        );
        assert!(response.headers().get(header::SET_COOKIE).is_none());
        let body = to_bytes(response.into_body(), 1024)
            .await
            .expect("bounded response");
        assert_eq!(body.as_ref(), br#"{"error":"invalid_token"}"#);

        let response = auth_error_with_clear_cookie(StatusCode::OK, "logged_out");
        assert_eq!(
            response.headers().get(header::SET_COOKIE),
            Some(&HeaderValue::from_static(
                "pov_refresh_local=; Path=/api/auth; HttpOnly; SameSite=Strict; Max-Age=0"
            ))
        );
    }
}
