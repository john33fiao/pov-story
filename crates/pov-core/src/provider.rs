use std::{
    error::Error,
    fmt,
    future::{Future, ready},
    io::{self, Read},
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    num::NonZeroU16,
    time::{Duration, Instant},
};

use sha2::{Digest, Sha256};

const MAX_IDENTIFIER_BYTES: usize = 128;
const SYNTHETIC_DOMAIN: &[u8] = b"pov-story:synthetic-provider:v1\0";

#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct Sha256Digest([u8; 32]);

impl Sha256Digest {
    #[must_use]
    pub fn of(bytes: &[u8]) -> Self {
        Self(Sha256::digest(bytes).into())
    }

    pub fn of_reader(mut reader: impl Read) -> io::Result<Self> {
        let mut hasher = Sha256::new();
        let mut buffer = [0_u8; 64 * 1024];
        loop {
            match reader.read(&mut buffer) {
                Ok(0) => return Ok(Self(hasher.finalize().into())),
                Ok(read) => hasher.update(&buffer[..read]),
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => return Err(error),
            }
        }
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub(crate) const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub fn to_hex(self) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut encoded = String::with_capacity(64);
        for byte in self.0 {
            encoded.push(char::from(HEX[usize::from(byte >> 4)]));
            encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
        encoded
    }
}

impl fmt::Debug for Sha256Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Sha256Digest([REDACTED])")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderIdentifierKind {
    Backend,
    RuntimeBuild,
    ArtifactRevision,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderConfigError {
    EmptyIdentifier(ProviderIdentifierKind),
    InvalidIdentifier(ProviderIdentifierKind),
    EmptyArtifact,
}

impl fmt::Display for ProviderConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyIdentifier(kind) => write!(formatter, "{kind:?} identifier is empty"),
            Self::InvalidIdentifier(kind) => {
                write!(formatter, "{kind:?} identifier is not a safe version label")
            }
            Self::EmptyArtifact => formatter.write_str("provider artifact bytes are empty"),
        }
    }
}

impl Error for ProviderConfigError {}

macro_rules! provider_identifier {
    ($name:ident, $kind:expr) => {
        #[derive(Clone, Eq, Hash, PartialEq)]
        pub struct $name(Box<str>);

        impl $name {
            pub fn try_new(value: impl AsRef<str>) -> Result<Self, ProviderConfigError> {
                let value = value.as_ref();
                validate_identifier(value, $kind)?;
                Ok(Self(value.into()))
            }

            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter
                    .debug_tuple(stringify!($name))
                    .field(&self.0)
                    .finish()
            }
        }
    };
}

provider_identifier!(BackendId, ProviderIdentifierKind::Backend);
provider_identifier!(RuntimeBuildId, ProviderIdentifierKind::RuntimeBuild);
provider_identifier!(ArtifactRevision, ProviderIdentifierKind::ArtifactRevision);

fn validate_identifier(
    value: &str,
    kind: ProviderIdentifierKind,
) -> Result<(), ProviderConfigError> {
    if value.is_empty() {
        return Err(ProviderConfigError::EmptyIdentifier(kind));
    }
    let starts_and_ends_with_alphanumeric = value
        .as_bytes()
        .first()
        .is_some_and(u8::is_ascii_alphanumeric)
        && value
            .as_bytes()
            .last()
            .is_some_and(u8::is_ascii_alphanumeric);
    if value.len() > MAX_IDENTIFIER_BYTES
        || !starts_and_ends_with_alphanumeric
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'+'))
    {
        return Err(ProviderConfigError::InvalidIdentifier(kind));
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderArtifact {
    backend: BackendId,
    runtime_build: RuntimeBuildId,
    revision: ArtifactRevision,
    sha256: Sha256Digest,
}

impl ProviderArtifact {
    pub fn from_bytes(
        backend: BackendId,
        runtime_build: RuntimeBuildId,
        revision: ArtifactRevision,
        artifact_bytes: &[u8],
    ) -> Result<Self, ProviderConfigError> {
        if artifact_bytes.is_empty() {
            return Err(ProviderConfigError::EmptyArtifact);
        }
        Ok(Self {
            backend,
            runtime_build,
            revision,
            sha256: Sha256Digest::of(artifact_bytes),
        })
    }

    #[must_use]
    pub fn backend(&self) -> &BackendId {
        &self.backend
    }

    #[must_use]
    pub fn runtime_build(&self) -> &RuntimeBuildId {
        &self.runtime_build
    }

    #[must_use]
    pub fn revision(&self) -> &ArtifactRevision {
        &self.revision
    }

    #[must_use]
    pub const fn sha256(&self) -> Sha256Digest {
        self.sha256
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct ProviderProvenance {
    artifact: ProviderArtifact,
    input_sha256: Sha256Digest,
    elapsed: Duration,
}

impl ProviderProvenance {
    #[must_use]
    pub fn from_input_bytes(
        artifact: ProviderArtifact,
        canonical_input_bytes: &[u8],
        elapsed: Duration,
    ) -> Self {
        Self {
            artifact,
            input_sha256: Sha256Digest::of(canonical_input_bytes),
            elapsed,
        }
    }

    #[must_use]
    pub const fn artifact(&self) -> &ProviderArtifact {
        &self.artifact
    }

    #[must_use]
    pub const fn input_sha256(&self) -> Sha256Digest {
        self.input_sha256
    }

    #[must_use]
    pub const fn elapsed(&self) -> Duration {
        self.elapsed
    }
}

impl fmt::Debug for ProviderProvenance {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderProvenance")
            .field("artifact", &self.artifact)
            .field("input_sha256", &"[REDACTED]")
            .field("elapsed", &self.elapsed)
            .finish()
    }
}

pub struct ProviderResult<T> {
    output: T,
    provenance: ProviderProvenance,
}

impl<T> ProviderResult<T> {
    #[must_use]
    pub const fn new(output: T, provenance: ProviderProvenance) -> Self {
        Self { output, provenance }
    }

    #[must_use]
    pub const fn output(&self) -> &T {
        &self.output
    }

    #[must_use]
    pub const fn provenance(&self) -> &ProviderProvenance {
        &self.provenance
    }

    #[must_use]
    pub fn into_parts(self) -> (T, ProviderProvenance) {
        (self.output, self.provenance)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderErrorKind {
    InvalidRequest,
    Unavailable,
    Cancelled,
    ProtocolFailure,
    BackendFailure,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProviderError {
    kind: ProviderErrorKind,
}

impl ProviderError {
    #[must_use]
    pub const fn new(kind: ProviderErrorKind) -> Self {
        Self { kind }
    }

    #[must_use]
    pub const fn kind(self) -> ProviderErrorKind {
        self.kind
    }
}

impl fmt::Display for ProviderError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "provider failed: {:?}", self.kind)
    }
}

impl Error for ProviderError {}

pub trait LlmProvider: Send + Sync {
    type Request: Send;
    type Output: Send;

    fn generate(
        &self,
        request: Self::Request,
    ) -> impl Future<Output = Result<ProviderResult<Self::Output>, ProviderError>> + Send;
}

pub trait Transcriber: Send + Sync {
    type Request: Send;
    type Output: Send;

    fn transcribe(
        &self,
        request: Self::Request,
    ) -> impl Future<Output = Result<ProviderResult<Self::Output>, ProviderError>> + Send;
}

pub trait Embedder: Send + Sync {
    type Request: Send;
    type Output: Send;

    fn embed(
        &self,
        request: Self::Request,
    ) -> impl Future<Output = Result<ProviderResult<Self::Output>, ProviderError>> + Send;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderCapability {
    Generate,
    Transcribe,
    Embed,
}

impl ProviderCapability {
    const fn domain_tag(self) -> &'static [u8] {
        match self {
            Self::Generate => b"generate\0",
            Self::Transcribe => b"transcribe\0",
            Self::Embed => b"embed\0",
        }
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct SyntheticInput(Vec<u8>);

impl SyntheticInput {
    #[must_use]
    pub fn new(bytes: impl Into<Vec<u8>>) -> Self {
        Self(bytes.into())
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for SyntheticInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SyntheticInput")
            .field("bytes", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SyntheticOutput {
    capability: ProviderCapability,
    digest: Sha256Digest,
}

impl SyntheticOutput {
    #[must_use]
    pub const fn capability(self) -> ProviderCapability {
        self.capability
    }

    #[must_use]
    pub const fn digest(self) -> Sha256Digest {
        self.digest
    }
}

#[derive(Clone, Debug)]
pub struct DeterministicFakeProvider {
    artifact: ProviderArtifact,
}

impl DeterministicFakeProvider {
    #[must_use]
    pub const fn new(artifact: ProviderArtifact) -> Self {
        Self { artifact }
    }

    fn execute(
        &self,
        capability: ProviderCapability,
        input: SyntheticInput,
    ) -> ProviderResult<SyntheticOutput> {
        let started = Instant::now();
        let mut output_hasher = Sha256::new();
        output_hasher.update(SYNTHETIC_DOMAIN);
        output_hasher.update(capability.domain_tag());
        output_hasher.update(input.as_bytes());
        let output = SyntheticOutput {
            capability,
            digest: Sha256Digest(output_hasher.finalize().into()),
        };
        ProviderResult::new(
            output,
            ProviderProvenance::from_input_bytes(
                self.artifact.clone(),
                input.as_bytes(),
                started.elapsed(),
            ),
        )
    }
}

impl LlmProvider for DeterministicFakeProvider {
    type Request = SyntheticInput;
    type Output = SyntheticOutput;

    fn generate(
        &self,
        request: Self::Request,
    ) -> impl Future<Output = Result<ProviderResult<Self::Output>, ProviderError>> + Send {
        ready(Ok(self.execute(ProviderCapability::Generate, request)))
    }
}

impl Transcriber for DeterministicFakeProvider {
    type Request = SyntheticInput;
    type Output = SyntheticOutput;

    fn transcribe(
        &self,
        request: Self::Request,
    ) -> impl Future<Output = Result<ProviderResult<Self::Output>, ProviderError>> + Send {
        ready(Ok(self.execute(ProviderCapability::Transcribe, request)))
    }
}

impl Embedder for DeterministicFakeProvider {
    type Request = SyntheticInput;
    type Output = SyntheticOutput;

    fn embed(
        &self,
        request: Self::Request,
    ) -> impl Future<Output = Result<ProviderResult<Self::Output>, ProviderError>> + Send {
        ready(Ok(self.execute(ProviderCapability::Embed, request)))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LoopbackEndpointError {
    UnassignedPort,
    NotExactIpv4Loopback,
}

impl fmt::Display for LoopbackEndpointError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnassignedPort => formatter.write_str("provider endpoint port must be assigned"),
            Self::NotExactIpv4Loopback => {
                formatter.write_str("provider endpoint must be exact IPv4 loopback")
            }
        }
    }
}

impl Error for LoopbackEndpointError {}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct LoopbackEndpoint(SocketAddrV4);

impl LoopbackEndpoint {
    #[must_use]
    pub const fn new(port: NonZeroU16) -> Self {
        Self(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port.get()))
    }

    #[must_use]
    pub const fn socket_addr(self) -> SocketAddrV4 {
        self.0
    }
}

impl TryFrom<SocketAddr> for LoopbackEndpoint {
    type Error = LoopbackEndpointError;

    fn try_from(address: SocketAddr) -> Result<Self, Self::Error> {
        match address {
            SocketAddr::V4(address) if *address.ip() == Ipv4Addr::LOCALHOST => {
                let port =
                    NonZeroU16::new(address.port()).ok_or(LoopbackEndpointError::UnassignedPort)?;
                Ok(Self::new(port))
            }
            SocketAddr::V4(_) | SocketAddr::V6(_) => {
                Err(LoopbackEndpointError::NotExactIpv4Loopback)
            }
        }
    }
}
