use std::{
    env,
    error::Error,
    fmt, io,
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::Stdio,
    time::{Duration, Instant},
};

use getrandom::fill as random_fill;
use nix::{
    sys::signal::{Signal, killpg},
    unistd::Pid,
};
use rustix::{io::Errno, process::test_kill_process_group};
use serde_json::{Value, json};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    process::{Child, Command},
    sync::Mutex,
    time,
};
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

use crate::{
    job::{GenerationCompletion, GenerationDispatchMode, GenerationSource},
    provider::{ArtifactRevision, BackendId, RuntimeBuildId, Sha256Digest},
};

const DEFAULT_PORT: u16 = 18_081;
const MODEL_ALIAS: &str = "pov-story-local-v1";
const READINESS_TIMEOUT: Duration = Duration::from_secs(3 * 60);
const GENERATION_TIMEOUT: Duration = Duration::from_secs(5 * 60);
const CLEANUP_TIMEOUT: Duration = Duration::from_secs(5);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(2);
const READINESS_REQUEST_TIMEOUT: Duration = Duration::from_secs(2);
const START_POLL_INTERVAL: Duration = Duration::from_millis(250);
const MAX_HTTP_BYTES: usize = 96 * 1024;
const MAX_HEADER_BYTES: usize = 32 * 1024;
const MAX_GENERATION_BYTES: usize = 64 * 1024;

const REQUIRED_ENVIRONMENT: [&str; 6] = [
    "POV_LLM_SERVER_BIN",
    "POV_LLM_SERVER_SHA256",
    "POV_LLM_RUNTIME_BUILD",
    "POV_LLM_MODEL_PATH",
    "POV_LLM_MODEL_SHA256",
    "POV_LLM_MODEL_REVISION",
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LoopbackLlmMode {
    Disabled,
    Unavailable,
    Ready,
}

impl LoopbackLlmMode {
    #[must_use]
    pub const fn dispatch_mode(self) -> GenerationDispatchMode {
        match self {
            Self::Disabled => GenerationDispatchMode::Disabled,
            Self::Unavailable | Self::Ready => GenerationDispatchMode::Enabled,
        }
    }
}

#[derive(Clone)]
struct LoopbackLlmConfig {
    server_bin: PathBuf,
    server_sha256: Sha256Digest,
    runtime_build: RuntimeBuildId,
    model_path: PathBuf,
    model_sha256: Sha256Digest,
    model_revision: ArtifactRevision,
    port: u16,
}

impl fmt::Debug for LoopbackLlmConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LoopbackLlmConfig")
            .field("server_bin", &"[REDACTED]")
            .field("server_sha256", &self.server_sha256)
            .field("runtime_build", &self.runtime_build)
            .field("model_path", &"[REDACTED]")
            .field("model_sha256", &self.model_sha256)
            .field("model_revision", &self.model_revision)
            .field("port", &self.port)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LoopbackGenerationErrorKind {
    ProviderUnavailable,
    Timeout,
    ExecutionFailed,
    Cancelled,
    CleanupUncertain,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LoopbackGenerationError {
    kind: LoopbackGenerationErrorKind,
}

impl LoopbackGenerationError {
    const fn new(kind: LoopbackGenerationErrorKind) -> Self {
        Self { kind }
    }

    #[must_use]
    pub const fn kind(self) -> LoopbackGenerationErrorKind {
        self.kind
    }
}

impl fmt::Display for LoopbackGenerationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "loopback generation failed: {:?}", self.kind)
    }
}

impl Error for LoopbackGenerationError {}

struct ProviderProcess {
    child: Child,
    group_leader: Pid,
    api_key: Zeroizing<String>,
}

#[derive(Default)]
struct ProviderState {
    process: Option<ProviderProcess>,
}

pub struct LoopbackLlmRuntime {
    mode: LoopbackLlmMode,
    config: Option<LoopbackLlmConfig>,
    scratch_root: PathBuf,
    state: Mutex<ProviderState>,
}

impl fmt::Debug for LoopbackLlmRuntime {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LoopbackLlmRuntime")
            .field("mode", &self.mode)
            .field("config", &self.config)
            .field("scratch_root", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

impl LoopbackLlmRuntime {
    pub fn from_environment(scratch_root: impl Into<PathBuf>) -> Self {
        let scratch_root = scratch_root.into();
        match read_environment_config() {
            EnvironmentConfig::Disabled => Self {
                mode: LoopbackLlmMode::Disabled,
                config: None,
                scratch_root,
                state: Mutex::new(ProviderState::default()),
            },
            EnvironmentConfig::Unavailable => Self {
                mode: LoopbackLlmMode::Unavailable,
                config: None,
                scratch_root,
                state: Mutex::new(ProviderState::default()),
            },
            EnvironmentConfig::Ready(config) => Self {
                mode: LoopbackLlmMode::Ready,
                config: Some(config),
                scratch_root,
                state: Mutex::new(ProviderState::default()),
            },
        }
    }

    #[must_use]
    pub const fn mode(&self) -> LoopbackLlmMode {
        self.mode
    }

    #[cfg(test)]
    pub(crate) fn test_unavailable(scratch_root: impl Into<PathBuf>) -> Self {
        Self {
            mode: LoopbackLlmMode::Unavailable,
            config: None,
            scratch_root: scratch_root.into(),
            state: Mutex::new(ProviderState::default()),
        }
    }

    #[cfg(test)]
    pub(crate) async fn test_unauthenticated_inference_is_rejected(&self) -> bool {
        let Some(config) = self.config.as_ref() else {
            return false;
        };
        let Ok(request) = canonical_request("authentication probe") else {
            return false;
        };
        http_request(
            config.port,
            "POST",
            "/v1/chat/completions",
            None,
            Some(&request),
        )
        .await
        .is_ok_and(|response| response.status == 401)
    }

    #[cfg(test)]
    pub(crate) async fn test_listener_is_absent(&self) -> bool {
        match self.config.as_ref() {
            Some(config) => !port_is_occupied(config.port).await,
            None => false,
        }
    }

    pub async fn generate(
        &self,
        source: &GenerationSource,
        cancellation: &CancellationToken,
    ) -> Result<GenerationCompletion, LoopbackGenerationError> {
        self.generate_with_timeout(source, cancellation, GENERATION_TIMEOUT)
            .await
    }

    async fn generate_with_timeout(
        &self,
        source: &GenerationSource,
        cancellation: &CancellationToken,
        generation_timeout: Duration,
    ) -> Result<GenerationCompletion, LoopbackGenerationError> {
        let Some(config) = self.config.as_ref() else {
            return Err(LoopbackGenerationError::new(
                LoopbackGenerationErrorKind::ProviderUnavailable,
            ));
        };
        let mut state = self.state.lock().await;
        self.ensure_running(&mut state, config, cancellation)
            .await?;
        let process = state.process.as_mut().ok_or_else(|| unavailable())?;
        let canonical_input_sha256 = Sha256Digest::of(source.content().as_bytes());
        let request = canonical_request(source.content())?;
        let started = Instant::now();
        let response = tokio::select! {
            biased;
            () = cancellation.cancelled() => {
                let cleanup = cleanup_process(&mut state.process).await;
                return Err(if cleanup.is_ok() {
                    LoopbackGenerationError::new(LoopbackGenerationErrorKind::Cancelled)
                } else {
                    cleanup_uncertain()
                });
            }
            response = time::timeout(
                generation_timeout,
                http_request(
                    config.port,
                    "POST",
                    "/v1/chat/completions",
                    Some(process.api_key.as_str()),
                    Some(&request),
                ),
            ) => response,
        };
        let response = match response {
            Ok(Ok(response)) => response,
            Ok(Err(_)) => {
                let cleanup = cleanup_process(&mut state.process).await;
                return Err(if cleanup.is_ok() {
                    LoopbackGenerationError::new(LoopbackGenerationErrorKind::ExecutionFailed)
                } else {
                    cleanup_uncertain()
                });
            }
            Err(_) => {
                let cleanup = cleanup_process(&mut state.process).await;
                return Err(if cleanup.is_ok() {
                    LoopbackGenerationError::new(LoopbackGenerationErrorKind::Timeout)
                } else {
                    cleanup_uncertain()
                });
            }
        };
        if response.status != 200 {
            let cleanup = cleanup_process(&mut state.process).await;
            return Err(if cleanup.is_ok() {
                LoopbackGenerationError::new(LoopbackGenerationErrorKind::ExecutionFailed)
            } else {
                cleanup_uncertain()
            });
        }
        let content = match parse_generation_content(&response.body) {
            Ok(content) => content,
            Err(error) => {
                return Err(if cleanup_process(&mut state.process).await.is_ok() {
                    error
                } else {
                    cleanup_uncertain()
                });
            }
        };
        Ok(GenerationCompletion {
            output: content,
            provider_backend_id: BackendId::try_new("llama.cpp").map_err(|_| unavailable())?,
            runtime_build: config.runtime_build.clone(),
            runtime_sha256: config.server_sha256,
            model_revision: config.model_revision.clone(),
            model_sha256: config.model_sha256,
            canonical_input_sha256,
            elapsed: started.elapsed(),
        })
    }

    pub async fn shutdown(&self) -> Result<(), LoopbackGenerationError> {
        let mut state = self.state.lock().await;
        cleanup_process(&mut state.process)
            .await
            .map_err(|_| cleanup_uncertain())
    }

    async fn ensure_running(
        &self,
        state: &mut ProviderState,
        config: &LoopbackLlmConfig,
        cancellation: &CancellationToken,
    ) -> Result<(), LoopbackGenerationError> {
        if let Some(process) = state.process.as_mut() {
            match process.child.try_wait() {
                Ok(None)
                    if process_readiness(process, config.port).await == ProcessReadiness::Ready =>
                {
                    return Ok(());
                }
                Ok(None) => {
                    if cleanup_process(&mut state.process).await.is_err() {
                        return Err(cleanup_uncertain());
                    }
                }
                Ok(Some(_)) | Err(_) => {
                    if cleanup_process(&mut state.process).await.is_err() {
                        return Err(cleanup_uncertain());
                    }
                }
            }
        }
        validate_scratch_root(&self.scratch_root).map_err(|_| unavailable())?;
        validate_artifacts(config).await?;
        if port_is_occupied(config.port).await {
            return Err(unavailable());
        }
        let api_key = generate_api_key()?;
        let mut command = Command::new(&config.server_bin);
        command
            .arg("--model")
            .arg(&config.model_path)
            .args([
                "--host",
                "127.0.0.1",
                "--port",
                &config.port.to_string(),
                "--ctx-size",
                "8192",
                "--parallel",
                "1",
                "--gpu-layers",
                "all",
                "--no-webui",
                "--no-ui-mcp-proxy",
                "--no-agent",
                "--no-slots",
                "--no-cache-prompt",
                "--reasoning",
                "off",
                "--jinja",
                "--alias",
                MODEL_ALIAS,
                "--log-disable",
            ])
            .env_clear()
            .env("LLAMA_API_KEY", api_key.as_str())
            .env("HOME", &self.scratch_root)
            .env("TMPDIR", &self.scratch_root)
            .env("XDG_CACHE_HOME", &self.scratch_root)
            .env("XDG_CONFIG_HOME", &self.scratch_root)
            .env("XDG_DATA_HOME", &self.scratch_root)
            .env("LANG", "C")
            .env("LC_ALL", "C")
            .current_dir(&self.scratch_root)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .process_group(0);
        let child = command.spawn().map_err(|_| unavailable())?;
        let group_leader = child
            .id()
            .and_then(|id| i32::try_from(id).ok())
            .map(Pid::from_raw)
            .ok_or_else(unavailable)?;
        state.process = Some(ProviderProcess {
            child,
            group_leader,
            api_key,
        });
        let readiness_deadline = time::Instant::now() + READINESS_TIMEOUT;
        loop {
            if cancellation.is_cancelled() {
                let cleanup = cleanup_process(&mut state.process).await;
                return Err(if cleanup.is_ok() {
                    LoopbackGenerationError::new(LoopbackGenerationErrorKind::Cancelled)
                } else {
                    cleanup_uncertain()
                });
            }
            let Some(process) = state.process.as_mut() else {
                return Err(unavailable());
            };
            match process.child.try_wait() {
                Ok(None) => {}
                Ok(Some(_)) | Err(_) => {
                    let cleanup = cleanup_process(&mut state.process).await;
                    return Err(if cleanup.is_ok() {
                        unavailable()
                    } else {
                        cleanup_uncertain()
                    });
                }
            }
            match process_readiness(process, config.port).await {
                ProcessReadiness::Ready => return Ok(()),
                ProcessReadiness::IdentityMismatch => {
                    let cleanup = cleanup_process(&mut state.process).await;
                    return Err(if cleanup.is_ok() {
                        unavailable()
                    } else {
                        cleanup_uncertain()
                    });
                }
                ProcessReadiness::Pending => {}
            }
            if time::Instant::now() >= readiness_deadline {
                let cleanup = cleanup_process(&mut state.process).await;
                return Err(if cleanup.is_ok() {
                    unavailable()
                } else {
                    cleanup_uncertain()
                });
            }
            time::sleep(START_POLL_INTERVAL).await;
        }
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum ProcessReadiness {
    Pending,
    Ready,
    IdentityMismatch,
}

async fn process_readiness(process: &ProviderProcess, port: u16) -> ProcessReadiness {
    let health = time::timeout(
        READINESS_REQUEST_TIMEOUT,
        http_request(port, "GET", "/health", Some(process.api_key.as_str()), None),
    )
    .await;
    if !health.is_ok_and(|response| response.is_ok_and(|response| response.status == 200)) {
        return ProcessReadiness::Pending;
    }
    let models = time::timeout(
        READINESS_REQUEST_TIMEOUT,
        http_request(
            port,
            "GET",
            "/v1/models",
            Some(process.api_key.as_str()),
            None,
        ),
    )
    .await;
    match models {
        Ok(Ok(response)) if response.status == 200 && model_identity_matches(&response.body) => {
            ProcessReadiness::Ready
        }
        Ok(Ok(response)) if response.status == 200 => ProcessReadiness::IdentityMismatch,
        Ok(Ok(_)) | Ok(Err(_)) | Err(_) => ProcessReadiness::Pending,
    }
}

enum EnvironmentConfig {
    Disabled,
    Unavailable,
    Ready(LoopbackLlmConfig),
}

fn read_environment_config() -> EnvironmentConfig {
    let present = REQUIRED_ENVIRONMENT.map(|name| env::var_os(name));
    let configured = present.iter().filter(|value| value.is_some()).count();
    let port_present = env::var_os("POV_LLM_PORT").is_some();
    if configured == 0 && !port_present {
        return EnvironmentConfig::Disabled;
    }
    if configured != REQUIRED_ENVIRONMENT.len() {
        return EnvironmentConfig::Unavailable;
    }
    let text = |index: usize| present[index].clone()?.into_string().ok();
    let Some(server_sha256) = text(1).and_then(|value| parse_sha256(&value)) else {
        return EnvironmentConfig::Unavailable;
    };
    let Some(runtime_build) = text(2).and_then(|value| RuntimeBuildId::try_new(value).ok()) else {
        return EnvironmentConfig::Unavailable;
    };
    let Some(model_sha256) = text(4).and_then(|value| parse_sha256(&value)) else {
        return EnvironmentConfig::Unavailable;
    };
    let Some(model_revision) = text(5).and_then(|value| ArtifactRevision::try_new(value).ok())
    else {
        return EnvironmentConfig::Unavailable;
    };
    let port = match env::var("POV_LLM_PORT") {
        Ok(value) => match value.parse::<u16>() {
            Ok(0) | Err(_) => return EnvironmentConfig::Unavailable,
            Ok(port) => port,
        },
        Err(env::VarError::NotPresent) => DEFAULT_PORT,
        Err(env::VarError::NotUnicode(_)) => return EnvironmentConfig::Unavailable,
    };
    let server_bin = PathBuf::from(present[0].clone().expect("complete environment"));
    let model_path = PathBuf::from(present[3].clone().expect("complete environment"));
    if validate_artifact_path(&server_bin, true).is_err()
        || validate_artifact_path(&model_path, false).is_err()
    {
        return EnvironmentConfig::Unavailable;
    }
    EnvironmentConfig::Ready(LoopbackLlmConfig {
        server_bin,
        server_sha256,
        runtime_build,
        model_path,
        model_sha256,
        model_revision,
        port,
    })
}

fn validate_artifact_path(path: &Path, executable: bool) -> io::Result<()> {
    if !path.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "path is not absolute",
        ));
    }
    let metadata = std::fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "artifact is not a regular file",
        ));
    }
    if std::fs::canonicalize(path)? != path {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "artifact path is not canonical",
        ));
    }
    if executable && metadata.permissions().mode() & 0o111 == 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "server is not executable",
        ));
    }
    Ok(())
}

fn validate_scratch_root(path: &Path) -> io::Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "scratch root is not a trusted directory",
            ));
        }
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => std::fs::create_dir_all(path)?,
        Err(error) => return Err(error),
    }
    let metadata = std::fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || std::fs::canonicalize(path)? != path
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "scratch root is not trusted",
        ));
    }
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    let metadata = std::fs::symlink_metadata(path)?;
    if metadata.permissions().mode() & 0o077 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "scratch root permissions are not private",
        ));
    }
    Ok(())
}

async fn validate_artifacts(config: &LoopbackLlmConfig) -> Result<(), LoopbackGenerationError> {
    let config = config.clone();
    tokio::task::spawn_blocking(move || {
        validate_artifact_path(&config.server_bin, true)?;
        validate_artifact_path(&config.model_path, false)?;
        let mut server = std::fs::File::open(&config.server_bin)?;
        if Sha256Digest::of_reader(&mut server)? != config.server_sha256 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "server hash mismatch",
            ));
        }
        let mut model = std::fs::File::open(&config.model_path)?;
        if Sha256Digest::of_reader(&mut model)? != config.model_sha256 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "model hash mismatch",
            ));
        }
        Ok::<(), io::Error>(())
    })
    .await
    .map_err(|_| unavailable())?
    .map_err(|_| unavailable())
}

fn canonical_request(content: &str) -> Result<Vec<u8>, LoopbackGenerationError> {
    serde_json::to_vec(&json!({
        "chat_template_kwargs": {"enable_thinking": false},
        "max_tokens": 512,
        "messages": [{"content": content, "role": "user"}],
        "model": MODEL_ALIAS,
        "stream": false,
        "temperature": 0
    }))
    .map_err(|_| LoopbackGenerationError::new(LoopbackGenerationErrorKind::ExecutionFailed))
}

fn parse_generation_content(bytes: &[u8]) -> Result<String, LoopbackGenerationError> {
    let response: Value = serde_json::from_slice(bytes)
        .map_err(|_| LoopbackGenerationError::new(LoopbackGenerationErrorKind::ExecutionFailed))?;
    let message = response
        .get("choices")
        .and_then(Value::as_array)
        .and_then(|choices| choices.first())
        .and_then(|choice| choice.get("message"))
        .ok_or_else(|| {
            LoopbackGenerationError::new(LoopbackGenerationErrorKind::ExecutionFailed)
        })?;
    if message
        .get("reasoning_content")
        .is_some_and(|reasoning| !reasoning.is_null())
    {
        return Err(LoopbackGenerationError::new(
            LoopbackGenerationErrorKind::ExecutionFailed,
        ));
    }
    let content = message
        .get("content")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            LoopbackGenerationError::new(LoopbackGenerationErrorKind::ExecutionFailed)
        })?;
    if content.is_empty() || content.len() > MAX_GENERATION_BYTES {
        return Err(LoopbackGenerationError::new(
            LoopbackGenerationErrorKind::ExecutionFailed,
        ));
    }
    Ok(content.to_owned())
}

fn model_identity_matches(bytes: &[u8]) -> bool {
    serde_json::from_slice::<Value>(bytes)
        .ok()
        .and_then(|value| value.get("data").and_then(Value::as_array).cloned())
        .is_some_and(|models| {
            models.len() == 1
                && models[0]
                    .get("id")
                    .and_then(Value::as_str)
                    .is_some_and(|id| id == MODEL_ALIAS)
        })
}

struct HttpResponse {
    status: u16,
    body: Vec<u8>,
}

async fn http_request(
    port: u16,
    method: &str,
    path: &str,
    api_key: Option<&str>,
    body: Option<&[u8]>,
) -> io::Result<HttpResponse> {
    let address = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port));
    let mut stream = time::timeout(CONNECT_TIMEOUT, TcpStream::connect(address))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "loopback connect timed out"))??;
    let body = body.unwrap_or_default();
    let mut request = format!(
        "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\nContent-Length: {}\r\n",
        body.len()
    );
    if !body.is_empty() {
        request.push_str("Content-Type: application/json\r\n");
    }
    if let Some(api_key) = api_key {
        request.push_str("Authorization: Bearer ");
        request.push_str(api_key);
        request.push_str("\r\n");
    }
    request.push_str("\r\n");
    stream.write_all(request.as_bytes()).await?;
    if !body.is_empty() {
        stream.write_all(body).await?;
    }
    stream.shutdown().await?;
    let mut bytes = Vec::new();
    stream
        .take(u64::try_from(MAX_HTTP_BYTES + 1).expect("bounded HTTP limit"))
        .read_to_end(&mut bytes)
        .await?;
    if bytes.len() > MAX_HTTP_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "HTTP response too large",
        ));
    }
    parse_http_response(&bytes)
}

fn parse_http_response(bytes: &[u8]) -> io::Result<HttpResponse> {
    let separator = bytes
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "HTTP headers missing"))?;
    if separator > MAX_HEADER_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "HTTP headers too large",
        ));
    }
    let headers = std::str::from_utf8(&bytes[..separator])
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "HTTP headers are not UTF-8"))?;
    let mut lines = headers.split("\r\n");
    let status = lines
        .next()
        .and_then(|line| line.split_ascii_whitespace().nth(1))
        .and_then(|value| value.parse::<u16>().ok())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "HTTP status missing"))?;
    let chunked = lines.any(|line| {
        line.split_once(':').is_some_and(|(name, value)| {
            name.eq_ignore_ascii_case("transfer-encoding")
                && value.trim().eq_ignore_ascii_case("chunked")
        })
    });
    let body = &bytes[separator + 4..];
    let body = if chunked {
        decode_chunked(body)?
    } else {
        body.to_vec()
    };
    if body.len() > MAX_GENERATION_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "HTTP body too large",
        ));
    }
    Ok(HttpResponse { status, body })
}

fn decode_chunked(mut bytes: &[u8]) -> io::Result<Vec<u8>> {
    let mut decoded = Vec::new();
    loop {
        let end = bytes
            .windows(2)
            .position(|window| window == b"\r\n")
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "chunk size missing"))?;
        let size = std::str::from_utf8(&bytes[..end])
            .ok()
            .and_then(|value| value.split(';').next())
            .and_then(|value| usize::from_str_radix(value, 16).ok())
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid chunk size"))?;
        bytes = &bytes[end + 2..];
        if size == 0 {
            return Ok(decoded);
        }
        if size > bytes.len() || bytes.get(size..size + 2) != Some(b"\r\n") {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "truncated chunk",
            ));
        }
        if decoded.len().saturating_add(size) > MAX_GENERATION_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "chunked body too large",
            ));
        }
        decoded.extend_from_slice(&bytes[..size]);
        bytes = &bytes[size + 2..];
    }
}

async fn port_is_occupied(port: u16) -> bool {
    let address = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port));
    time::timeout(Duration::from_millis(200), TcpStream::connect(address))
        .await
        .is_ok_and(|result| result.is_ok())
}

fn generate_api_key() -> Result<Zeroizing<String>, LoopbackGenerationError> {
    let mut bytes = Zeroizing::new([0_u8; 32]);
    random_fill(bytes.as_mut()).map_err(|_| unavailable())?;
    let mut key = Zeroizing::new(String::with_capacity(64));
    for byte in bytes.iter() {
        use std::fmt::Write as _;
        write!(key, "{byte:02x}").map_err(|_| unavailable())?;
    }
    Ok(key)
}

async fn cleanup_process(process: &mut Option<ProviderProcess>) -> Result<(), ()> {
    let Some(mut process) = process.take() else {
        return Ok(());
    };
    let _ = killpg(process.group_leader, Signal::SIGTERM);
    let deadline = time::Instant::now() + CLEANUP_TIMEOUT;
    loop {
        match process.child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if time::Instant::now() < deadline => {
                time::sleep(Duration::from_millis(50)).await;
            }
            Ok(None) => {
                let _ = killpg(process.group_leader, Signal::SIGKILL);
                if time::timeout(CLEANUP_TIMEOUT, process.child.wait())
                    .await
                    .is_err()
                {
                    return Err(());
                }
                break;
            }
            Err(_) => return Err(()),
        }
    }
    let Some(group_leader) = rustix::process::Pid::from_raw(process.group_leader.as_raw()) else {
        return Err(());
    };
    match test_kill_process_group(group_leader) {
        Err(Errno::SRCH) => Ok(()),
        _ => Err(()),
    }
}

fn parse_sha256(value: &str) -> Option<Sha256Digest> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    let mut bytes = [0_u8; 32];
    for (index, slot) in bytes.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16).ok()?;
    }
    Some(Sha256Digest::from_bytes(bytes))
}

const fn unavailable() -> LoopbackGenerationError {
    LoopbackGenerationError::new(LoopbackGenerationErrorKind::ProviderUnavailable)
}

const fn cleanup_uncertain() -> LoopbackGenerationError {
    LoopbackGenerationError::new(LoopbackGenerationErrorKind::CleanupUncertain)
}

#[cfg(test)]
mod tests {
    use std::{os::unix::fs::PermissionsExt, sync::Arc, time::Duration};

    use tempfile::TempDir;
    use tokio_util::sync::CancellationToken;

    use crate::{
        conversation::{ConversationEventId, ConversationId},
        job::GenerationSource,
        provider::{ArtifactRevision, RuntimeBuildId, Sha256Digest},
    };

    use super::{
        LoopbackGenerationErrorKind, LoopbackLlmConfig, LoopbackLlmMode, LoopbackLlmRuntime,
        MODEL_ALIAS, ProviderState, canonical_request, decode_chunked, http_request,
        model_identity_matches, parse_generation_content, parse_http_response, parse_sha256,
        validate_scratch_root,
    };

    const FAKE_SERVER: &str = r#"#!/usr/bin/python3
import argparse
import http.server
import json
import os
import signal
import time

parser = argparse.ArgumentParser(add_help=False)
parser.add_argument('--model')
parser.add_argument('--port', type=int)
args, _ = parser.parse_known_args()
mode = open(args.model, encoding='utf-8').read().strip()
key = os.environ['LLAMA_API_KEY']

class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'
    def log_message(self, *args):
        pass
    def authorized(self):
        return self.headers.get('Authorization') == 'Bearer ' + key
    def reply(self, status, value):
        body = json.dumps(value, separators=(',', ':')).encode()
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Connection', 'close')
        self.end_headers()
        self.wfile.write(body)
    def do_GET(self):
        if not self.authorized():
            self.reply(401, {'error': 'unauthorized'})
        elif self.path == '/health':
            self.reply(200, {'status': 'ok'})
        elif self.path == '/v1/models':
            model = 'foreign-model' if mode == 'wrong_identity' else 'pov-story-local-v1'
            self.reply(200, {'data': [{'id': model}]})
        else:
            self.reply(404, {'error': 'not_found'})
    def do_POST(self):
        if not self.authorized():
            self.reply(401, {'error': 'unauthorized'})
            return
        length = int(self.headers.get('Content-Length', '0'))
        request = json.loads(self.rfile.read(length))
        if mode == 'crash':
            os.kill(os.getpid(), signal.SIGKILL)
        if mode == 'timeout':
            time.sleep(60)
        content = request['messages'][0]['content']
        self.reply(200, {'choices': [{'message': {'content': 'fake: ' + content, 'reasoning_content': None}}]})

http.server.ThreadingHTTPServer(('127.0.0.1', args.port), Handler).serve_forever()
"#;

    struct FakeRuntime {
        _directory: TempDir,
        runtime: Arc<LoopbackLlmRuntime>,
    }

    async fn fake_runtime(mode: &str, bad_server_hash: bool) -> Option<FakeRuntime> {
        if !std::path::Path::new("/usr/bin/python3").is_file() {
            return None;
        }
        let listener = match tokio::net::TcpListener::bind("127.0.0.1:0").await {
            Ok(listener) => listener,
            Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => return None,
            Err(error) => panic!("reserve fake port: {error}"),
        };
        let port = listener.local_addr().expect("fake listener address").port();
        drop(listener);
        let directory = tempfile::tempdir().expect("fake provider directory");
        let root = std::fs::canonicalize(directory.path()).expect("canonical fake directory");
        let server_bin = root.join("fake-llm-server.py");
        std::fs::write(&server_bin, FAKE_SERVER).expect("write fake server");
        std::fs::set_permissions(&server_bin, std::fs::Permissions::from_mode(0o700))
            .expect("fake server permissions");
        let model_path = root.join("fake-model.txt");
        std::fs::write(&model_path, mode).expect("write fake model");
        let server_sha256 = if bad_server_hash {
            Sha256Digest::of(b"wrong hash")
        } else {
            Sha256Digest::of(FAKE_SERVER.as_bytes())
        };
        let runtime = Arc::new(LoopbackLlmRuntime {
            mode: LoopbackLlmMode::Ready,
            config: Some(LoopbackLlmConfig {
                server_bin,
                server_sha256,
                runtime_build: RuntimeBuildId::try_new("fake-build").expect("runtime build"),
                model_sha256: Sha256Digest::of(mode.as_bytes()),
                model_path,
                model_revision: ArtifactRevision::try_new("fake-model").expect("model revision"),
                port,
            }),
            scratch_root: root.join("scratch"),
            state: tokio::sync::Mutex::new(ProviderState::default()),
        });
        Some(FakeRuntime {
            _directory: directory,
            runtime,
        })
    }

    fn fake_source() -> GenerationSource {
        GenerationSource {
            conversation_id: ConversationId::new(),
            source_event_id: ConversationEventId::new(),
            content: "exact source".to_owned(),
        }
    }

    #[test]
    fn canonical_request_is_fixed_and_contains_only_one_source_message() {
        let request = canonical_request("exact source").expect("canonical request");
        let value: serde_json::Value = serde_json::from_slice(&request).expect("request JSON");
        assert_eq!(value["model"], MODEL_ALIAS);
        assert_eq!(value["temperature"], 0);
        assert_eq!(value["max_tokens"], 512);
        assert_eq!(value["stream"], false);
        assert_eq!(value["chat_template_kwargs"]["enable_thinking"], false);
        assert_eq!(value["messages"].as_array().expect("messages").len(), 1);
        assert_eq!(value["messages"][0]["role"], "user");
        assert_eq!(value["messages"][0]["content"], "exact source");
    }

    #[test]
    fn bounded_http_and_provider_payload_parsing_is_fail_closed() {
        let response = b"HTTP/1.1 200 OK\r\nContent-Length: 68\r\n\r\n{\"choices\":[{\"message\":{\"content\":\"assistant\",\"reasoning_content\":null}}]}";
        let parsed = parse_http_response(response).expect("HTTP response");
        assert_eq!(parsed.status, 200);
        assert_eq!(
            parse_generation_content(&parsed.body).expect("assistant content"),
            "assistant"
        );
        assert!(parse_generation_content(b"{\"choices\":[]}").is_err());
        assert!(
            parse_generation_content(
                br#"{"choices":[{"message":{"content":"assistant","reasoning_content":"hidden"}}]}"#
            )
            .is_err()
        );
        assert!(decode_chunked(b"3\r\nabc\r\n0\r\n\r\n").is_ok());
        assert!(decode_chunked(b"3\r\nab").is_err());
    }

    #[test]
    fn identity_and_digest_parsing_are_exact() {
        assert!(model_identity_matches(
            br#"{"data":[{"id":"pov-story-local-v1"}]}"#
        ));
        assert!(!model_identity_matches(br#"{"data":[{"id":"foreign"}]}"#));
        assert!(parse_sha256(&"ab".repeat(32)).is_some());
        assert!(parse_sha256(&"ab".repeat(31)).is_none());
    }

    #[test]
    fn scratch_symlink_is_rejected_without_changing_target_permissions() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().expect("scratch test directory");
        let target = directory.path().join("target");
        std::fs::create_dir(&target).expect("scratch target");
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o755))
            .expect("target permissions");
        let scratch = directory.path().join("scratch");
        symlink(&target, &scratch).expect("scratch symlink");

        assert!(validate_scratch_root(&scratch).is_err());
        let mode = std::fs::symlink_metadata(&target)
            .expect("target metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o755);
    }

    #[tokio::test]
    async fn fake_provider_round_trip_rejects_unauthenticated_inference() {
        use tokio::{
            io::{AsyncReadExt, AsyncWriteExt},
            net::TcpListener,
        };

        let listener = match TcpListener::bind("127.0.0.1:0").await {
            Ok(listener) => listener,
            Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => return,
            Err(error) => panic!("fake loopback listener: {error}"),
        };
        let port = listener.local_addr().expect("listener address").port();
        let server = tokio::spawn(async move {
            for authenticated in [false, true] {
                let (mut stream, _) = listener.accept().await.expect("fake request");
                let mut request = vec![0_u8; 16 * 1024];
                let read = stream.read(&mut request).await.expect("read fake request");
                request.truncate(read);
                let request = String::from_utf8(request).expect("request UTF-8");
                let has_key = request.contains("Authorization: Bearer synthetic-key\r\n");
                assert_eq!(has_key, authenticated);
                let (status, body) = if authenticated {
                    assert!(request.contains("exact source"));
                    (
                        "200 OK",
                        r#"{"choices":[{"message":{"content":"synthetic assistant","reasoning_content":null}}]}"#,
                    )
                } else {
                    ("401 Unauthorized", r#"{"error":"unauthorized"}"#)
                };
                let response = format!(
                    "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                stream
                    .write_all(response.as_bytes())
                    .await
                    .expect("write fake response");
            }
        });

        let unauthorized = http_request(
            port,
            "POST",
            "/v1/chat/completions",
            None,
            Some(&canonical_request("exact source").expect("canonical request")),
        )
        .await
        .expect("unauthenticated HTTP response");
        assert_eq!(unauthorized.status, 401);
        let authorized = http_request(
            port,
            "POST",
            "/v1/chat/completions",
            Some("synthetic-key"),
            Some(&canonical_request("exact source").expect("canonical request")),
        )
        .await
        .expect("authenticated HTTP response");
        assert_eq!(authorized.status, 200);
        assert_eq!(
            parse_generation_content(&authorized.body).expect("provider content"),
            "synthetic assistant"
        );
        server.await.expect("fake server joins");
    }

    #[tokio::test]
    async fn supervised_fake_provider_starts_restarts_and_rejects_bad_artifacts_or_identity() {
        let Some(fake) = fake_runtime("normal", false).await else {
            return;
        };
        let source = fake_source();
        let cancellation = CancellationToken::new();
        let first = fake
            .runtime
            .generate(&source, &cancellation)
            .await
            .expect("first fake generation");
        assert_eq!(first.output, "fake: exact source");
        assert!(
            fake.runtime
                .test_unauthenticated_inference_is_rejected()
                .await
        );
        fake.runtime.shutdown().await.expect("first shutdown");
        assert!(fake.runtime.test_listener_is_absent().await);
        let second = fake
            .runtime
            .generate(&source, &cancellation)
            .await
            .expect("restart fake generation");
        assert_eq!(second.output, first.output);
        fake.runtime.shutdown().await.expect("second shutdown");
        assert!(fake.runtime.test_listener_is_absent().await);

        let Some(wrong_identity) = fake_runtime("wrong_identity", false).await else {
            return;
        };
        let error = wrong_identity
            .runtime
            .generate(&fake_source(), &CancellationToken::new())
            .await
            .expect_err("wrong model identity");
        assert_eq!(
            error.kind(),
            LoopbackGenerationErrorKind::ProviderUnavailable
        );
        assert!(wrong_identity.runtime.test_listener_is_absent().await);

        let Some(bad_hash) = fake_runtime("normal", true).await else {
            return;
        };
        let error = bad_hash
            .runtime
            .generate(&fake_source(), &CancellationToken::new())
            .await
            .expect_err("server hash mismatch");
        assert_eq!(
            error.kind(),
            LoopbackGenerationErrorKind::ProviderUnavailable
        );
        assert!(bad_hash.runtime.test_listener_is_absent().await);

        let Some(port_collision) = fake_runtime("normal", false).await else {
            return;
        };
        let port = port_collision
            .runtime
            .config
            .as_ref()
            .expect("fake config")
            .port;
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", port))
            .await
            .expect("occupy fake provider port");
        let error = port_collision
            .runtime
            .generate(&fake_source(), &CancellationToken::new())
            .await
            .expect_err("occupied provider port");
        assert_eq!(
            error.kind(),
            LoopbackGenerationErrorKind::ProviderUnavailable
        );
        drop(listener);
        assert!(port_collision.runtime.test_listener_is_absent().await);
    }

    #[tokio::test]
    async fn supervised_fake_provider_classifies_crash_and_cancel_with_confirmed_cleanup() {
        let Some(crashing) = fake_runtime("crash", false).await else {
            return;
        };
        let error = crashing
            .runtime
            .generate(&fake_source(), &CancellationToken::new())
            .await
            .expect_err("provider crash");
        assert_eq!(error.kind(), LoopbackGenerationErrorKind::ExecutionFailed);
        assert!(crashing.runtime.test_listener_is_absent().await);

        let Some(timing_out) = fake_runtime("timeout", false).await else {
            return;
        };
        let cancellation = CancellationToken::new();
        let cancel = cancellation.clone();
        let cancel_task = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(200)).await;
            cancel.cancel();
        });
        let error = timing_out
            .runtime
            .generate(&fake_source(), &cancellation)
            .await
            .expect_err("provider cancellation");
        cancel_task.await.expect("cancel task");
        assert_eq!(error.kind(), LoopbackGenerationErrorKind::Cancelled);
        assert!(timing_out.runtime.test_listener_is_absent().await);

        let Some(timing_out) = fake_runtime("timeout", false).await else {
            return;
        };
        let error = timing_out
            .runtime
            .generate_with_timeout(
                &fake_source(),
                &CancellationToken::new(),
                Duration::from_millis(200),
            )
            .await
            .expect_err("provider timeout");
        assert_eq!(error.kind(), LoopbackGenerationErrorKind::Timeout);
        assert!(timing_out.runtime.test_listener_is_absent().await);
    }
}
