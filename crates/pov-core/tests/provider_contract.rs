use std::{
    cell::Cell,
    io::Cursor,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
    num::NonZeroU16,
    rc::Rc,
};

use pov_core::provider::{
    ArtifactRevision, BackendId, DeterministicFakeProvider, Embedder, LlmProvider,
    LoopbackEndpoint, LoopbackEndpointError, ProviderArtifact, ProviderCapability,
    ProviderConfigError, ProviderIdentifierKind, ProviderProvenance, RuntimeBuildId, Sha256Digest,
    SyntheticInput, Transcriber,
};

fn synthetic_provider() -> DeterministicFakeProvider {
    let artifact = ProviderArtifact::from_bytes(
        BackendId::try_new("deterministic-fake").expect("valid backend"),
        RuntimeBuildId::try_new("fake-runtime-1").expect("valid runtime build"),
        ArtifactRevision::try_new("synthetic-v1").expect("valid artifact revision"),
        b"synthetic provider artifact v1",
    )
    .expect("non-empty synthetic artifact");
    DeterministicFakeProvider::new(artifact)
}

#[tokio::test]
async fn deterministic_fake_ports_preserve_capability_and_actual_input_provenance() {
    let provider = synthetic_provider();
    let input = b"synthetic input only";

    let first = provider
        .generate(SyntheticInput::new(input))
        .await
        .expect("fake generation succeeds");
    let repeated = provider
        .generate(SyntheticInput::new(input))
        .await
        .expect("repeated fake generation succeeds");
    let transcript = provider
        .transcribe(SyntheticInput::new(input))
        .await
        .expect("fake transcription succeeds");
    let embedding = provider
        .embed(SyntheticInput::new(input))
        .await
        .expect("fake embedding succeeds");

    assert_eq!(first.output().capability(), ProviderCapability::Generate);
    assert_eq!(first.output().digest(), repeated.output().digest());
    assert_ne!(first.output().digest(), transcript.output().digest());
    assert_ne!(first.output().digest(), embedding.output().digest());
    assert_eq!(first.provenance().input_sha256(), Sha256Digest::of(input));
    assert_eq!(
        first.provenance().artifact().backend().as_str(),
        "deterministic-fake"
    );
    assert_eq!(
        first.provenance().artifact().runtime_build().as_str(),
        "fake-runtime-1"
    );
    assert_eq!(
        first.provenance().artifact().revision().as_str(),
        "synthetic-v1"
    );
    assert_eq!(
        first.provenance().artifact().sha256(),
        Sha256Digest::of(b"synthetic provider artifact v1")
    );
}

#[tokio::test]
async fn deterministic_fake_changes_output_when_canonical_input_changes() {
    let provider = synthetic_provider();
    let first = provider
        .generate(SyntheticInput::new(b"first"))
        .await
        .expect("first fake generation succeeds");
    let second = provider
        .generate(SyntheticInput::new(b"second"))
        .await
        .expect("second fake generation succeeds");

    assert_ne!(first.output().digest(), second.output().digest());
    assert_ne!(
        first.provenance().input_sha256(),
        second.provenance().input_sha256()
    );
}

#[test]
fn input_digest_is_redacted_from_debug_output() {
    let digest = Sha256Digest::of(b"low-entropy synthetic input");
    let rendered = format!("{digest:?}");

    assert_eq!(rendered, "Sha256Digest([REDACTED])");
    assert!(!rendered.contains(&digest.to_hex()));
}

#[test]
fn streaming_sha256_matches_the_in_memory_digest() {
    let bytes = b"synthetic artifact bytes";
    let streamed = Sha256Digest::of_reader(Cursor::new(bytes)).expect("stream hash succeeds");

    assert_eq!(streamed, Sha256Digest::of(bytes));
}

#[test]
fn public_provenance_constructor_hashes_canonical_input_bytes_itself() {
    let artifact = ProviderArtifact::from_bytes(
        BackendId::try_new("fixture").expect("valid backend"),
        RuntimeBuildId::try_new("runtime-1").expect("valid runtime"),
        ArtifactRevision::try_new("artifact-1").expect("valid revision"),
        b"artifact bytes",
    )
    .expect("non-empty artifact");
    let provenance = ProviderProvenance::from_input_bytes(
        artifact,
        b"canonical input bytes",
        Default::default(),
    );

    assert_eq!(
        provenance.input_sha256(),
        Sha256Digest::of(b"canonical input bytes")
    );
}

#[test]
fn provider_identifiers_reject_path_like_or_unbounded_labels() {
    for invalid in [".", "..", "-leading", "trailing-", "path/segment"] {
        assert_eq!(
            BackendId::try_new(invalid),
            Err(ProviderConfigError::InvalidIdentifier(
                ProviderIdentifierKind::Backend
            ))
        );
    }
    assert_eq!(
        BackendId::try_new("x".repeat(129)),
        Err(ProviderConfigError::InvalidIdentifier(
            ProviderIdentifierKind::Backend
        ))
    );
}

#[test]
fn provider_identifier_stores_the_exact_value_that_was_validated() {
    struct SwitchingLabel {
        calls: Rc<Cell<usize>>,
    }

    impl AsRef<str> for SwitchingLabel {
        fn as_ref(&self) -> &str {
            let call = self.calls.get();
            self.calls.set(call + 1);
            if call == 0 {
                "validated-label"
            } else {
                "../unvalidated"
            }
        }
    }

    let calls = Rc::new(Cell::new(0));
    let identifier = BackendId::try_new(SwitchingLabel {
        calls: Rc::clone(&calls),
    })
    .expect("first and only value is valid");

    assert_eq!(identifier.as_str(), "validated-label");
    assert_eq!(calls.get(), 1);
}

#[test]
fn loopback_endpoint_accepts_only_assigned_exact_ipv4_loopback() {
    let endpoint = LoopbackEndpoint::new(NonZeroU16::new(8081).expect("non-zero port"));
    assert_eq!(
        endpoint.socket_addr(),
        SocketAddrV4::new(Ipv4Addr::LOCALHOST, 8081)
    );

    assert_eq!(
        LoopbackEndpoint::try_from(SocketAddr::V4(SocketAddrV4::new(
            Ipv4Addr::UNSPECIFIED,
            8081,
        ))),
        Err(LoopbackEndpointError::NotExactIpv4Loopback)
    );
    assert_eq!(
        LoopbackEndpoint::try_from(SocketAddr::V4(SocketAddrV4::new(
            Ipv4Addr::new(127, 0, 0, 2),
            8081,
        ))),
        Err(LoopbackEndpointError::NotExactIpv4Loopback)
    );
    assert_eq!(
        LoopbackEndpoint::try_from(SocketAddr::V6(SocketAddrV6::new(
            Ipv6Addr::LOCALHOST,
            8081,
            0,
            0,
        ))),
        Err(LoopbackEndpointError::NotExactIpv4Loopback)
    );
    assert_eq!(
        LoopbackEndpoint::try_from(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0,))),
        Err(LoopbackEndpointError::UnassignedPort)
    );
}
