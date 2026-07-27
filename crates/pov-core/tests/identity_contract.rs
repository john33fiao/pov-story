use pov_core::{
    identity::{CorrelationId, Revision, SourceId},
    repository::{RepositoryError, advance_revision},
};
use uuid::Uuid;

#[test]
fn source_and_correlation_ids_use_uuid_v4() {
    let source = SourceId::new();
    let correlation = CorrelationId::new();

    assert_eq!(source.as_uuid().get_version_num(), 4);
    assert_eq!(correlation.as_uuid().get_version_num(), 4);
}

#[test]
fn persisted_public_ids_rehydrate_only_from_rfc_uuid_v4_values() {
    let source_uuid = SourceId::new().as_uuid();
    let correlation_uuid = CorrelationId::new().as_uuid();

    assert_eq!(
        SourceId::from_uuid(source_uuid)
            .expect("generated source ID rehydrates")
            .as_uuid(),
        source_uuid
    );
    assert_eq!(
        CorrelationId::from_uuid(correlation_uuid)
            .expect("generated correlation ID rehydrates")
            .as_uuid(),
        correlation_uuid
    );
    assert!(SourceId::from_uuid(Uuid::nil()).is_none());
    assert!(CorrelationId::from_uuid(Uuid::max()).is_none());
}

#[test]
fn revision_advances_only_from_the_expected_current_value() {
    let current = Revision::new(7).expect("positive revision");

    assert_eq!(
        advance_revision(current, current).expect("matching revision"),
        Revision::new(8).expect("next revision")
    );
    assert_eq!(
        advance_revision(current, Revision::new(6).expect("stale revision")),
        Err(RepositoryError::RevisionConflict {
            expected: Revision::new(6).expect("stale revision"),
            actual: current,
        })
    );
}
