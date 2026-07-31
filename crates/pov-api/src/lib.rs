//! POV Story local HTTP surface.

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
#[cfg(unix)]
use std::{
    collections::VecDeque,
    convert::Infallible,
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
    extract::{DefaultBodyLimit, Path, State},
    http::{HeaderMap, HeaderName, HeaderValue},
    routing::post,
};
#[cfg(unix)]
use futures_util::stream;
#[cfg(unix)]
use pov_core::{
    auth::{
        AuthProfile, AuthRuntime, CredentialMutationOutcome, IssuedSession, LoginOutcome,
        LoginRequest, LogoutAllOutcome, LogoutOutcome, NormalizedPassword, RefreshOutcome,
        SecretBytes,
    },
    conversation::{
        AppendUserEvent, ConversationError, ConversationId, ConversationRepository,
        ConversationTimeline, IdempotencyKey, MAX_USER_EVENT_CONTENT_BYTES,
    },
    generation_worker::GenerationWorkerSignal,
    identity::{Revision, VerifiedAuthContext},
    job::{
        CancelJob, EnqueueJob, GenerationDispatchMode, GenerationJobSummary, JobEnqueueKey,
        JobEventCursor, JobEventPage, JobId, JobKind, JobMutationKey, JobQueueError,
        JobQueueRepository, JobSnapshot, SequencedJobEvent,
    },
    loopback_llm::LoopbackLlmRuntime,
    storage::StoreSet,
};
use rust_embed::Embed;
#[cfg(any(unix, test))]
use serde::{
    Deserialize, Deserializer,
    de::{self, MapAccess, Visitor},
};
#[cfg(unix)]
use tokio::time::{Duration, Instant};
#[cfg(unix)]
use zeroize::Zeroizing;

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
const MAX_CONVERSATION_REQUEST_BYTES: usize = MAX_USER_EVENT_CONTENT_BYTES + 4096;
#[cfg(unix)]
const MAX_JOB_MUTATION_REQUEST_BYTES: usize = 1024;
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
#[cfg(unix)]
const LAST_EVENT_ID_HEADER: HeaderName = HeaderName::from_static("last-event-id");
#[cfg(unix)]
const JOB_EVENT_POLL_INTERVAL: Duration = Duration::from_millis(500);
#[cfg(unix)]
const JOB_EVENT_HEARTBEAT_INTERVAL: Duration = Duration::from_secs(10);
#[cfg(unix)]
const JOB_EVENT_AUTH_INTERVAL: Duration = Duration::from_secs(15);

pub fn app() -> Router {
    let api = Router::new()
        .route("/health", get(health))
        .fallback(api_not_found);

    Router::new().nest("/api", api).fallback(serve_web_asset)
}

#[cfg(unix)]
#[derive(Clone)]
struct ApiState {
    runtime: Arc<AuthRuntime>,
    stores: Arc<StoreSet>,
    generation: Option<ApiGeneration>,
}

#[cfg(unix)]
#[derive(Clone)]
pub struct ApiGeneration {
    runtime: Arc<LoopbackLlmRuntime>,
    signal: GenerationWorkerSignal,
}

#[cfg(unix)]
impl ApiGeneration {
    #[must_use]
    pub const fn new(runtime: Arc<LoopbackLlmRuntime>, signal: GenerationWorkerSignal) -> Self {
        Self { runtime, signal }
    }
}

#[cfg(unix)]
pub fn app_with_auth(runtime: Arc<AuthRuntime>, stores: Arc<StoreSet>) -> Router {
    app_with_state(ApiState {
        runtime,
        stores,
        generation: None,
    })
}

#[cfg(unix)]
pub fn app_with_generation(
    runtime: Arc<AuthRuntime>,
    stores: Arc<StoreSet>,
    generation: ApiGeneration,
) -> Router {
    app_with_state(ApiState {
        runtime,
        stores,
        generation: Some(generation),
    })
}

#[cfg(unix)]
fn app_with_state(state: ApiState) -> Router {
    let auth = Router::new()
        .route("/login", post(login))
        .route("/refresh", post(refresh))
        .route("/logout", post(logout))
        .route("/logout-all", post(logout_all))
        .route("/password", post(change_password))
        .route("/session", get(session_status))
        .layer(DefaultBodyLimit::max(MAX_AUTH_REQUEST_BYTES));
    let conversations = Router::new()
        .route("/conversations", get(list_conversations))
        .route("/conversations/{conversation_id}", get(read_conversation))
        .route(
            "/conversations/{conversation_id}/events",
            post(append_conversation_event),
        )
        .layer(DefaultBodyLimit::max(MAX_CONVERSATION_REQUEST_BYTES));
    let jobs = Router::new()
        .route("/jobs/events", get(poll_job_events))
        .route("/jobs/events/stream", get(stream_job_events))
        .route("/jobs/{job_id}/cancel", post(cancel_job))
        .layer(DefaultBodyLimit::max(MAX_JOB_MUTATION_REQUEST_BYTES));
    let api = Router::new()
        .route("/health", get(health))
        .nest("/auth", auth)
        .merge(conversations)
        .merge(jobs)
        .fallback(api_not_found)
        .with_state(state);

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

#[cfg(any(unix, test))]
struct AppendEventPayload {
    idempotency_key: String,
    expected_revision: Option<u64>,
    content: String,
}

#[cfg(any(unix, test))]
struct CancelJobPayload {
    idempotency_key: String,
    expected_revision: u64,
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

#[cfg(any(unix, test))]
impl<'de> Deserialize<'de> for AppendEventPayload {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct AppendEventVisitor;

        impl<'de> Visitor<'de> for AppendEventVisitor {
            type Value = AppendEventPayload;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("an exact conversation append object")
            }

            fn visit_map<M>(self, mut map: M) -> Result<Self::Value, M::Error>
            where
                M: MapAccess<'de>,
            {
                let mut key = None;
                let mut expected = None;
                let mut content = None;
                while let Some(field) = map.next_key::<String>()? {
                    match field.as_str() {
                        "idempotency_key" if key.is_none() => {
                            key = Some(map.next_value()?);
                        }
                        "expected_revision" if expected.is_none() => {
                            expected = Some(map.next_value::<Option<u64>>()?);
                        }
                        "content" if content.is_none() => {
                            content = Some(map.next_value()?);
                        }
                        "idempotency_key" | "expected_revision" | "content" => {
                            return Err(de::Error::duplicate_field("conversation append field"));
                        }
                        _ => {
                            return Err(de::Error::unknown_field("conversation append field", &[]));
                        }
                    }
                }
                let expected_revision = match expected {
                    None => None,
                    Some(Some(value)) => Some(value),
                    Some(None) => {
                        return Err(de::Error::custom(
                            "expected_revision must be absent or a positive integer",
                        ));
                    }
                };
                Ok(AppendEventPayload {
                    idempotency_key: key
                        .ok_or_else(|| de::Error::missing_field("idempotency_key"))?,
                    expected_revision,
                    content: content.ok_or_else(|| de::Error::missing_field("content"))?,
                })
            }
        }

        deserializer.deserialize_map(AppendEventVisitor)
    }
}

#[cfg(any(unix, test))]
impl<'de> Deserialize<'de> for CancelJobPayload {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct CancelJobVisitor;

        impl<'de> Visitor<'de> for CancelJobVisitor {
            type Value = CancelJobPayload;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("an exact job cancellation object")
            }

            fn visit_map<M>(self, mut map: M) -> Result<Self::Value, M::Error>
            where
                M: MapAccess<'de>,
            {
                let mut key = None;
                let mut expected = None;
                while let Some(field) = map.next_key::<String>()? {
                    match field.as_str() {
                        "idempotency_key" if key.is_none() => {
                            key = Some(map.next_value()?);
                        }
                        "expected_revision" if expected.is_none() => {
                            expected = Some(map.next_value()?);
                        }
                        "idempotency_key" | "expected_revision" => {
                            return Err(de::Error::duplicate_field("job cancellation field"));
                        }
                        _ => {
                            return Err(de::Error::unknown_field("job cancellation field", &[]));
                        }
                    }
                }
                Ok(CancelJobPayload {
                    idempotency_key: key
                        .ok_or_else(|| de::Error::missing_field("idempotency_key"))?,
                    expected_revision: expected
                        .ok_or_else(|| de::Error::missing_field("expected_revision"))?,
                })
            }
        }

        deserializer.deserialize_map(CancelJobVisitor)
    }
}

#[cfg(unix)]
async fn login(State(state): State<ApiState>, headers: HeaderMap, body: Bytes) -> Response {
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
async fn refresh(State(state): State<ApiState>, headers: HeaderMap, body: Bytes) -> Response {
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
async fn logout(State(state): State<ApiState>, headers: HeaderMap, body: Bytes) -> Response {
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
async fn logout_all(State(state): State<ApiState>, headers: HeaderMap, body: Bytes) -> Response {
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
    State(state): State<ApiState>,
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
async fn session_status(State(state): State<ApiState>, headers: HeaderMap) -> Response {
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
async fn poll_job_events(State(state): State<ApiState>, uri: Uri, headers: HeaderMap) -> Response {
    let after = match parse_poll_cursor(uri.query()) {
        Some(cursor) => cursor,
        None => return auth_error(StatusCode::BAD_REQUEST, "invalid_cursor"),
    };
    let auth = match verified_api_auth(&state, &headers, false).await {
        Ok(auth) => auth,
        Err(response) => return response,
    };
    match JobQueueRepository::new(&state.stores.conversation)
        .read_event_page(&auth, after)
        .await
    {
        Ok(page) => job_event_page_response(&page),
        Err(error) => job_event_error(error),
    }
}

#[cfg(unix)]
async fn stream_job_events(
    State(state): State<ApiState>,
    uri: Uri,
    headers: HeaderMap,
) -> Response {
    if uri.query().is_some() {
        return auth_error(StatusCode::BAD_REQUEST, "invalid_cursor");
    }
    let after = match parse_stream_cursor(&headers) {
        Some(cursor) => cursor,
        None => return auth_error(StatusCode::BAD_REQUEST, "invalid_cursor"),
    };
    let (auth, token) = match verified_stream_auth(&state, &headers).await {
        Ok(auth) => auth,
        Err(response) => return response,
    };
    let page = match JobQueueRepository::new(&state.stores.conversation)
        .read_event_page(&auth, after)
        .await
    {
        Ok(page) => page,
        Err(error) => return job_event_error(error),
    };
    let stream_state = JobEventStreamState::new(state, auth, token, page);
    let body_stream = stream::unfold(stream_state, |mut state| async move {
        state
            .next_frame()
            .await
            .map(|frame| (Ok::<Bytes, Infallible>(frame), state))
    });
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "text/event-stream; charset=utf-8")
        .header(header::CACHE_CONTROL, "no-store")
        .header(header::PRAGMA, "no-cache")
        .header(header::REFERRER_POLICY, "no-referrer")
        .body(Body::from_stream(body_stream))
        .expect("job event stream response headers are valid")
}

#[cfg(unix)]
struct JobEventStreamState {
    state: ApiState,
    auth: VerifiedAuthContext,
    token: Zeroizing<Vec<u8>>,
    cursor: JobEventCursor,
    frames: VecDeque<Bytes>,
    has_more: bool,
    next_poll: Instant,
    next_heartbeat: Instant,
    next_auth: Instant,
}

#[cfg(unix)]
impl JobEventStreamState {
    fn new(
        state: ApiState,
        auth: VerifiedAuthContext,
        token: Zeroizing<Vec<u8>>,
        page: JobEventPage,
    ) -> Self {
        let now = Instant::now();
        let mut stream = Self {
            state,
            auth,
            token,
            cursor: JobEventCursor::START,
            frames: VecDeque::new(),
            has_more: false,
            next_poll: now + JOB_EVENT_POLL_INTERVAL,
            next_heartbeat: now + JOB_EVENT_HEARTBEAT_INTERVAL,
            next_auth: now + JOB_EVENT_AUTH_INTERVAL,
        };
        stream.enqueue_page(&page);
        stream
    }

    fn enqueue_page(&mut self, page: &JobEventPage) {
        self.cursor = page.next_cursor();
        self.has_more = page.has_more();
        self.frames
            .extend(page.events().iter().map(job_event_sse_frame));
    }

    async fn next_frame(&mut self) -> Option<Bytes> {
        loop {
            if Instant::now() >= self.next_auth && !self.revalidate().await {
                return None;
            }
            if let Some(frame) = self.frames.pop_front() {
                return Some(frame);
            }
            if self.has_more {
                let page = self.read_page().await?;
                self.enqueue_page(&page);
                continue;
            }

            let deadline = self.next_poll.min(self.next_heartbeat).min(self.next_auth);
            tokio::time::sleep_until(deadline).await;
            let now = Instant::now();
            if now >= self.next_auth && !self.revalidate().await {
                return None;
            }
            if now >= self.next_poll {
                self.next_poll = now + JOB_EVENT_POLL_INTERVAL;
                let page = self.read_page().await?;
                self.enqueue_page(&page);
                if !self.frames.is_empty() {
                    continue;
                }
            }
            if now >= self.next_heartbeat {
                self.next_heartbeat = now + JOB_EVENT_HEARTBEAT_INTERVAL;
                return Some(Bytes::from_static(b": heartbeat\n\n"));
            }
        }
    }

    async fn read_page(&self) -> Option<JobEventPage> {
        JobQueueRepository::new(&self.state.stores.conversation)
            .read_event_page(&self.auth, self.cursor)
            .await
            .ok()
    }

    async fn revalidate(&mut self) -> bool {
        let Some(now_micros) = current_time_micros() else {
            return false;
        };
        match self
            .state
            .runtime
            .verify_access(
                AuthProfile::Local,
                SecretBytes::new(self.token.as_slice().to_vec()),
                now_micros,
            )
            .await
        {
            Ok(auth) => {
                self.auth = auth;
                self.next_auth = Instant::now() + JOB_EVENT_AUTH_INTERVAL;
                true
            }
            Err(_) => false,
        }
    }
}

#[cfg(unix)]
fn parse_poll_cursor(query: Option<&str>) -> Option<JobEventCursor> {
    let query = query?;
    let value = query.strip_prefix("after=")?;
    if value.contains('&') {
        return None;
    }
    value.parse().ok()
}

#[cfg(unix)]
fn parse_stream_cursor(headers: &HeaderMap) -> Option<JobEventCursor> {
    match exact_optional_header(headers, LAST_EVENT_ID_HEADER) {
        Ok(None) => Some(JobEventCursor::START),
        Ok(Some(value)) => value.parse().ok(),
        Err(()) => None,
    }
}

#[cfg(unix)]
fn job_event_value(sequenced: &SequencedJobEvent) -> serde_json::Value {
    let event = sequenced.event();
    serde_json::json!({
        "cursor": sequenced.cursor().to_string(),
        "event_id": event.id().to_string(),
        "job_id": event.job_id().to_string(),
        "conversation_id": event.conversation_id().to_string(),
        "source_event_id": event.source_event_id().to_string(),
        "job_revision": event.job_revision().get(),
        "kind": event.kind().as_str(),
        "state": event.state().as_str(),
        "attempt_id": event.attempt_id().map(|value| value.to_string()),
        "happened_at_micros": event.happened_at().get().to_string(),
        "queue_wait_micros": event.queue_wait_micros().map(|value| value.to_string()),
        "execution_micros": event.execution_micros().map(|value| value.to_string()),
        "failure_kind": event.failure().map(|value| value.as_str()),
        "correlation_id": event.correlation_id().to_string(),
    })
}

#[cfg(unix)]
fn job_event_page_value(page: &JobEventPage) -> serde_json::Value {
    serde_json::json!({
        "events": page.events().iter().map(job_event_value).collect::<Vec<_>>(),
        "next_cursor": page.next_cursor().to_string(),
        "has_more": page.has_more(),
    })
}

#[cfg(unix)]
fn job_event_page_response(page: &JobEventPage) -> Response {
    auth_json(StatusCode::OK, job_event_page_value(page), None)
}

#[cfg(unix)]
fn job_event_sse_frame(event: &SequencedJobEvent) -> Bytes {
    let data = serde_json::to_string(&job_event_value(event))
        .expect("job event JSON contains only serializable values");
    Bytes::from(format!(
        "event: job_status\nid: {}\ndata: {data}\n\n",
        event.cursor()
    ))
}

#[cfg(unix)]
fn job_event_error(error: JobQueueError) -> Response {
    match error {
        JobQueueError::InvalidCursor => auth_error(StatusCode::BAD_REQUEST, "invalid_cursor"),
        JobQueueError::CorruptStoredState | JobQueueError::BackendFailure => {
            auth_error(StatusCode::SERVICE_UNAVAILABLE, "storage_unavailable")
        }
        _ => auth_error(StatusCode::SERVICE_UNAVAILABLE, "storage_unavailable"),
    }
}

#[cfg(unix)]
async fn list_conversations(State(state): State<ApiState>, headers: HeaderMap) -> Response {
    let auth = match verified_api_auth(&state, &headers, false).await {
        Ok(auth) => auth,
        Err(response) => return response,
    };
    let repository = ConversationRepository::new(&state.stores.conversation);
    match repository.list_conversations(&auth).await {
        Ok(conversations) => {
            let conversations = conversations
                .into_iter()
                .map(|conversation| {
                    serde_json::json!({
                        "conversation_id": conversation.id().to_string(),
                        "revision": conversation.source().revision().get(),
                    })
                })
                .collect::<Vec<_>>();
            auth_json(
                StatusCode::OK,
                serde_json::json!({"conversations": conversations}),
                None,
            )
        }
        Err(error) => conversation_error(error),
    }
}

#[cfg(unix)]
async fn read_conversation(
    State(state): State<ApiState>,
    Path(conversation_id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let auth = match verified_api_auth(&state, &headers, false).await {
        Ok(auth) => auth,
        Err(response) => return response,
    };
    let conversation_id = match parse_conversation_id(&conversation_id) {
        Some(conversation_id) => conversation_id,
        None => return auth_error(StatusCode::BAD_REQUEST, "invalid_request"),
    };
    let repository = ConversationRepository::new(&state.stores.conversation);
    match repository.read_timeline(&auth, conversation_id).await {
        Ok(timeline) => {
            conversation_timeline_response(state.stores.as_ref(), &auth, &timeline).await
        }
        Err(error) => conversation_error(error),
    }
}

#[cfg(unix)]
async fn append_conversation_event(
    State(state): State<ApiState>,
    Path(conversation_id): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let auth = match verified_api_auth(&state, &headers, true).await {
        Ok(auth) => auth,
        Err(response) => return response,
    };
    let conversation_id = match parse_conversation_id(&conversation_id) {
        Some(conversation_id) => conversation_id,
        None => return auth_error(StatusCode::BAD_REQUEST, "invalid_request"),
    };
    let payload: AppendEventPayload = match serde_json::from_slice(&body) {
        Ok(payload) => payload,
        Err(_) => return auth_error(StatusCode::BAD_REQUEST, "invalid_request"),
    };
    let idempotency_key = match payload
        .idempotency_key
        .parse()
        .ok()
        .and_then(IdempotencyKey::from_uuid)
    {
        Some(key) => key,
        None => return auth_error(StatusCode::BAD_REQUEST, "invalid_request"),
    };
    let expected_revision = match payload.expected_revision {
        Some(value) => match Revision::new(value) {
            Some(revision) => Some(revision),
            None => return auth_error(StatusCode::BAD_REQUEST, "invalid_request"),
        },
        None => None,
    };
    let repository = ConversationRepository::new(&state.stores.conversation);
    let command = AppendUserEvent {
        conversation_id,
        expected_revision,
        idempotency_key,
        content: payload.content,
    };
    match repository.append_user_event(&auth, command).await {
        Ok(receipt) => {
            if let Some(generation) = &state.generation {
                if generation.runtime.mode().dispatch_mode() == GenerationDispatchMode::Enabled {
                    let queue = JobQueueRepository::new(&state.stores.conversation);
                    let _ = queue
                        .enqueue(
                            &auth,
                            EnqueueJob {
                                source_outbox_id: receipt.outbox.id(),
                                kind: JobKind::ConversationResponseV1,
                                idempotency_key: JobEnqueueKey::new(),
                            },
                        )
                        .await;
                }
                generation.signal.wake();
            }
            match repository.read_timeline(&auth, conversation_id).await {
                Ok(timeline) => {
                    conversation_timeline_response(state.stores.as_ref(), &auth, &timeline).await
                }
                Err(error) => conversation_error(error),
            }
        }
        Err(error) => conversation_error(error),
    }
}

#[cfg(unix)]
async fn cancel_job(
    State(state): State<ApiState>,
    Path(job_id): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let auth = match verified_api_auth(&state, &headers, true).await {
        Ok(auth) => auth,
        Err(response) => return response,
    };
    let job_id = match job_id.parse().ok().and_then(JobId::from_uuid) {
        Some(job_id) => job_id,
        None => return auth_error(StatusCode::BAD_REQUEST, "invalid_request"),
    };
    let payload: CancelJobPayload = match serde_json::from_slice(&body) {
        Ok(payload) => payload,
        Err(_) => return auth_error(StatusCode::BAD_REQUEST, "invalid_request"),
    };
    let idempotency_key = match payload
        .idempotency_key
        .parse()
        .ok()
        .and_then(JobMutationKey::from_uuid)
    {
        Some(key) => key,
        None => return auth_error(StatusCode::BAD_REQUEST, "invalid_request"),
    };
    let expected_revision = match Revision::new(payload.expected_revision) {
        Some(revision) => revision,
        None => return auth_error(StatusCode::BAD_REQUEST, "invalid_request"),
    };
    let queue = JobQueueRepository::new(&state.stores.conversation);
    match queue
        .request_cancel(
            &auth,
            CancelJob {
                job_id,
                expected_revision,
                idempotency_key,
            },
        )
        .await
    {
        Ok(receipt) => {
            if let Some(generation) = &state.generation {
                generation.signal.wake();
            }
            auth_json(
                StatusCode::OK,
                serde_json::json!({
                    "job": job_snapshot_value(&receipt.job),
                    "replayed": receipt.replayed,
                }),
                None,
            )
        }
        Err(error) => job_mutation_error(error),
    }
}

#[cfg(unix)]
async fn verified_api_auth(
    state: &ApiState,
    headers: &HeaderMap,
    mutation: bool,
) -> Result<VerifiedAuthContext, Response> {
    let headers_valid = if mutation {
        valid_mutation_headers(headers)
    } else {
        valid_local_host(headers)
    };
    if !headers_valid {
        return Err(auth_error(StatusCode::FORBIDDEN, "request_rejected"));
    }
    let Some(token) = bearer_token_bytes(headers) else {
        return Err(auth_error(StatusCode::UNAUTHORIZED, "invalid_token"));
    };
    let Some(now_micros) = current_time_micros() else {
        return Err(auth_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "authentication_unavailable",
        ));
    };
    state
        .runtime
        .verify_access(
            AuthProfile::Local,
            SecretBytes::new(token.as_slice().to_vec()),
            now_micros,
        )
        .await
        .map_err(|_| auth_error(StatusCode::UNAUTHORIZED, "invalid_token"))
}

#[cfg(unix)]
async fn verified_stream_auth(
    state: &ApiState,
    headers: &HeaderMap,
) -> Result<(VerifiedAuthContext, Zeroizing<Vec<u8>>), Response> {
    if !valid_local_host(headers) {
        return Err(auth_error(StatusCode::FORBIDDEN, "request_rejected"));
    }
    let Some(token) = bearer_token_bytes(headers) else {
        return Err(auth_error(StatusCode::UNAUTHORIZED, "invalid_token"));
    };
    let Some(now_micros) = current_time_micros() else {
        return Err(auth_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "authentication_unavailable",
        ));
    };
    let auth = state
        .runtime
        .verify_access(
            AuthProfile::Local,
            SecretBytes::new(token.as_slice().to_vec()),
            now_micros,
        )
        .await
        .map_err(|_| auth_error(StatusCode::UNAUTHORIZED, "invalid_token"))?;
    Ok((auth, token))
}

#[cfg(unix)]
fn parse_conversation_id(value: &str) -> Option<ConversationId> {
    value.parse().ok().and_then(ConversationId::from_uuid)
}

#[cfg(unix)]
async fn conversation_timeline_response(
    stores: &StoreSet,
    auth: &VerifiedAuthContext,
    timeline: &ConversationTimeline,
) -> Response {
    let events = timeline
        .events()
        .iter()
        .map(|event| {
            serde_json::json!({
                "event_id": event.id().to_string(),
                "revision": event.conversation_revision().get(),
                "kind": event.kind().as_str(),
                "content": event.content(),
                "correlation_id": event.correlation_id().to_string(),
            })
        })
        .collect::<Vec<_>>();
    let generation_jobs = match JobQueueRepository::new(&stores.conversation)
        .read_generation_jobs(auth, timeline.conversation().id())
        .await
    {
        Ok(jobs) => jobs.iter().map(generation_job_value).collect::<Vec<_>>(),
        Err(error) => return job_event_error(error),
    };
    auth_json(
        StatusCode::OK,
        serde_json::json!({
            "conversation_id": timeline.conversation().id().to_string(),
            "revision": timeline.conversation().source().revision().get(),
            "events": events,
            "generation_jobs": generation_jobs,
        }),
        None,
    )
}

#[cfg(unix)]
fn job_snapshot_value(job: &JobSnapshot) -> serde_json::Value {
    serde_json::json!({
        "job_id": job.id().to_string(),
        "source_outbox_id": job.source_outbox_id().to_string(),
        "kind": "conversation_response_v1",
        "state": job.state().as_str(),
        "revision": job.revision().get(),
        "attempts_started": job.attempts_started(),
        "max_attempts": job.max_attempts(),
        "queue_wait_micros": job.queue_wait_micros().to_string(),
        "execution_micros": job.execution_micros().to_string(),
    })
}

#[cfg(unix)]
fn generation_job_value(summary: &GenerationJobSummary) -> serde_json::Value {
    let mut value = job_snapshot_value(summary.job());
    let object = value
        .as_object_mut()
        .expect("job snapshot JSON is an object");
    object.insert(
        "conversation_id".to_owned(),
        serde_json::Value::String(summary.conversation_id().to_string()),
    );
    object.insert(
        "source_event_id".to_owned(),
        serde_json::Value::String(summary.source_event_id().to_string()),
    );
    object.insert(
        "failure_kind".to_owned(),
        summary
            .failure()
            .map(|failure| serde_json::Value::String(failure.as_str().to_owned()))
            .unwrap_or(serde_json::Value::Null),
    );
    value
}

#[cfg(unix)]
fn conversation_error(error: ConversationError) -> Response {
    match error {
        ConversationError::EmptyContent => auth_error(StatusCode::BAD_REQUEST, "invalid_content"),
        ConversationError::ContentTooLarge => {
            auth_error(StatusCode::PAYLOAD_TOO_LARGE, "content_too_large")
        }
        ConversationError::NotFound => auth_error(StatusCode::NOT_FOUND, "not_found"),
        ConversationError::IdempotencyConflict => {
            auth_error(StatusCode::CONFLICT, "idempotency_conflict")
        }
        ConversationError::RevisionConflict => {
            auth_error(StatusCode::CONFLICT, "revision_conflict")
        }
        ConversationError::RevisionExhausted => {
            auth_error(StatusCode::CONFLICT, "revision_exhausted")
        }
        ConversationError::CorruptStoredState | ConversationError::BackendFailure => {
            auth_error(StatusCode::SERVICE_UNAVAILABLE, "storage_unavailable")
        }
    }
}

#[cfg(unix)]
fn job_mutation_error(error: JobQueueError) -> Response {
    match error {
        JobQueueError::NotFound => auth_error(StatusCode::NOT_FOUND, "not_found"),
        JobQueueError::IdempotencyConflict => {
            auth_error(StatusCode::CONFLICT, "idempotency_conflict")
        }
        JobQueueError::RevisionConflict => auth_error(StatusCode::CONFLICT, "revision_conflict"),
        JobQueueError::InvalidTransition => auth_error(StatusCode::CONFLICT, "invalid_transition"),
        JobQueueError::CorruptStoredState | JobQueueError::BackendFailure => {
            auth_error(StatusCode::SERVICE_UNAVAILABLE, "storage_unavailable")
        }
        _ => auth_error(StatusCode::SERVICE_UNAVAILABLE, "storage_unavailable"),
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
fn bearer_token_bytes(headers: &HeaderMap) -> Option<Zeroizing<Vec<u8>>> {
    let value = exact_single_header(headers, header::AUTHORIZATION)?;
    let token = value.strip_prefix("Bearer ")?;
    if token.is_empty()
        || token
            .bytes()
            .any(|byte| !byte.is_ascii() || byte.is_ascii_whitespace())
    {
        return None;
    }
    Some(Zeroizing::new(token.as_bytes().to_vec()))
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

#[cfg(test)]
mod conversation_contract_tests {
    use super::{AppendEventPayload, CancelJobPayload};

    #[test]
    fn append_payload_requires_exact_fields_and_absent_or_numeric_revision() {
        let first: AppendEventPayload = serde_json::from_str(
            r#"{
                "idempotency_key":"a1b06fd4-39a2-4210-940c-ace9d47a610b",
                "content":"synthetic first note"
            }"#,
        )
        .expect("first append payload");
        assert_eq!(
            first.idempotency_key,
            "a1b06fd4-39a2-4210-940c-ace9d47a610b"
        );
        assert_eq!(first.expected_revision, None);
        assert_eq!(first.content, "synthetic first note");

        let later: AppendEventPayload = serde_json::from_str(
            r#"{
                "idempotency_key":"e76aa730-c29a-45e0-84fc-c9b88d819e69",
                "expected_revision":7,
                "content":"synthetic later note"
            }"#,
        )
        .expect("later append payload");
        assert_eq!(later.expected_revision, Some(7));

        for invalid in [
            r#"{"idempotency_key":"x","expected_revision":null,"content":"x"}"#,
            r#"{"idempotency_key":"x","content":"x","owner_id":"forged"}"#,
            r#"{"idempotency_key":"x","idempotency_key":"y","content":"x"}"#,
            r#"{"idempotency_key":"x"}"#,
        ] {
            assert!(serde_json::from_str::<AppendEventPayload>(invalid).is_err());
        }
    }

    #[test]
    fn cancel_payload_requires_exact_idempotency_key_and_revision() {
        let exact: CancelJobPayload = serde_json::from_str(
            r#"{
                "idempotency_key":"a1b06fd4-39a2-4210-940c-ace9d47a610b",
                "expected_revision":7
            }"#,
        )
        .expect("exact cancel payload");
        assert_eq!(exact.expected_revision, 7);
        for invalid in [
            r#"{"idempotency_key":"x"}"#,
            r#"{"expected_revision":7}"#,
            r#"{"idempotency_key":"x","expected_revision":7,"owner_id":"forged"}"#,
            r#"{"idempotency_key":"x","idempotency_key":"y","expected_revision":7}"#,
        ] {
            assert!(serde_json::from_str::<CancelJobPayload>(invalid).is_err());
        }
    }
}

#[cfg(all(test, unix))]
mod auth_http_tests {
    use axum::{
        body::to_bytes,
        http::{HeaderMap, HeaderValue, StatusCode, header},
    };

    use super::{
        CSRF_HEADER, FETCH_SITE_HEADER, LAST_EVENT_ID_HEADER, LOCAL_HOST, LOCAL_ORIGIN,
        LoginPayload, auth_error, auth_error_with_clear_cookie, bearer_token, bearer_token_bytes,
        job_event_error, local_issue_cookie, local_refresh_cookie, parse_poll_cursor,
        parse_stream_cursor, valid_mutation_headers,
    };
    use pov_core::job::{JobEventCursor, JobQueueError};

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

    #[test]
    fn job_event_cursor_inputs_are_exact_single_decimal_values() {
        assert_eq!(
            parse_poll_cursor(Some("after=0")),
            Some(JobEventCursor::START)
        );
        assert_eq!(
            parse_poll_cursor(Some("after=17"))
                .expect("valid polling cursor")
                .get(),
            17
        );
        for invalid in [
            None,
            Some(""),
            Some("after="),
            Some("after=01"),
            Some("after=17&after=18"),
            Some("after=17&unknown=1"),
            Some("unknown=17"),
        ] {
            assert_eq!(parse_poll_cursor(invalid), None);
        }

        let mut headers = HeaderMap::new();
        assert_eq!(parse_stream_cursor(&headers), Some(JobEventCursor::START));
        headers.insert(LAST_EVENT_ID_HEADER, HeaderValue::from_static("17"));
        assert_eq!(
            parse_stream_cursor(&headers)
                .expect("valid resume cursor")
                .get(),
            17
        );
        headers.append(LAST_EVENT_ID_HEADER, HeaderValue::from_static("18"));
        assert_eq!(parse_stream_cursor(&headers), None);
    }

    #[test]
    fn retained_bearer_is_exact_and_zeroizing() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer header.payload.signature"),
        );
        let token = bearer_token_bytes(&headers).expect("retained bearer");
        assert_eq!(token.as_slice(), b"header.payload.signature");
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

        let response = job_event_error(JobQueueError::InvalidCursor);
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            response.headers().get(header::CACHE_CONTROL),
            Some(&HeaderValue::from_static("no-store"))
        );
    }
}
