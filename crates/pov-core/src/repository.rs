use std::{error::Error, fmt, future::Future};

use crate::{
    identity::{OwnerId, Revision, SourceDomain, VerifiedAuthContext},
    storage::{DerivativeStoreBoundary, SourceStoreBoundary, StoreBoundary, StoreKind},
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RepositoryError {
    NotFound,
    BackendFailure,
    RevisionConflict {
        expected: Revision,
        actual: Revision,
    },
    RevisionExhausted {
        actual: Revision,
    },
}

impl fmt::Display for RepositoryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFound => formatter.write_str("record not found"),
            Self::BackendFailure => formatter.write_str("repository backend failure"),
            Self::RevisionConflict { expected, actual } => write!(
                formatter,
                "revision conflict: expected {}, actual {}",
                expected.get(),
                actual.get()
            ),
            Self::RevisionExhausted { actual } => {
                write!(formatter, "revision {} cannot advance", actual.get())
            }
        }
    }
}

impl Error for RepositoryError {}

pub fn advance_revision(
    current: Revision,
    expected: Revision,
) -> Result<Revision, RepositoryError> {
    if current != expected {
        return Err(RepositoryError::RevisionConflict {
            expected,
            actual: current,
        });
    }

    current
        .checked_next()
        .ok_or(RepositoryError::RevisionExhausted { actual: current })
}

#[derive(Clone, Copy, Debug)]
pub struct VerifiedOwnerScope<'a> {
    context: &'a VerifiedAuthContext,
}

impl<'a> VerifiedOwnerScope<'a> {
    #[must_use]
    pub const fn owner_id(self) -> OwnerId {
        self.context.owner_id()
    }

    pub fn ensure_record_owner(self, record_owner: OwnerId) -> Result<(), RepositoryError> {
        if self.owner_id() == record_owner {
            Ok(())
        } else {
            Err(RepositoryError::NotFound)
        }
    }
}

impl VerifiedAuthContext {
    #[must_use]
    pub const fn owner_scope(&self) -> VerifiedOwnerScope<'_> {
        VerifiedOwnerScope { context: self }
    }
}

pub trait RepositoryPort: Send + Sync {
    type Store: StoreBoundary;
    type Key: Copy + Send + Sync;
    type Record: Send;

    fn read_for_owner(
        &self,
        owner: VerifiedOwnerScope<'_>,
        key: Self::Key,
    ) -> impl Future<Output = Result<Self::Record, RepositoryError>> + Send;

    #[must_use]
    fn scope<'a>(&'a self, context: &'a VerifiedAuthContext) -> ScopedRepository<'a, Self>
    where
        Self: Sized,
    {
        ScopedRepository {
            repository: self,
            owner: context.owner_scope(),
        }
    }
}

pub trait SourceRepositoryPort: RepositoryPort
where
    Self::Store: SourceStoreBoundary,
{
    type CreateCommand: Send;
    type UpdateCommand: Send;

    fn create_for_owner(
        &self,
        owner: VerifiedOwnerScope<'_>,
        command: Self::CreateCommand,
    ) -> impl Future<Output = Result<Self::Record, RepositoryError>> + Send;

    fn revise_for_owner(
        &self,
        owner: VerifiedOwnerScope<'_>,
        key: Self::Key,
        expected: Revision,
        command: Self::UpdateCommand,
    ) -> impl Future<Output = Result<Self::Record, RepositoryError>> + Send;
}

pub trait DerivativeRepositoryPort: RepositoryPort
where
    Self::Store: DerivativeStoreBoundary,
{
}

#[derive(Debug)]
pub struct ScopedRepository<'a, R: RepositoryPort> {
    repository: &'a R,
    owner: VerifiedOwnerScope<'a>,
}

impl<'a, R: RepositoryPort> ScopedRepository<'a, R> {
    #[must_use]
    pub const fn owner(&self) -> VerifiedOwnerScope<'a> {
        self.owner
    }

    #[must_use]
    pub const fn store_kind(&self) -> StoreKind {
        R::Store::KIND
    }

    pub async fn read(&self, key: R::Key) -> Result<R::Record, RepositoryError> {
        self.repository.read_for_owner(self.owner, key).await
    }
}

impl<'a, R> ScopedRepository<'a, R>
where
    R: SourceRepositoryPort,
    R::Store: SourceStoreBoundary,
{
    #[must_use]
    pub const fn source_domain(&self) -> SourceDomain {
        R::Store::DOMAIN
    }

    pub async fn create(&self, command: R::CreateCommand) -> Result<R::Record, RepositoryError> {
        self.repository.create_for_owner(self.owner, command).await
    }

    pub async fn revise(
        &self,
        key: R::Key,
        expected: Revision,
        command: R::UpdateCommand,
    ) -> Result<R::Record, RepositoryError> {
        self.repository
            .revise_for_owner(self.owner, key, expected, command)
            .await
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::HashMap,
        sync::{Arc, Mutex},
    };

    use crate::identity::{
        CorrelationId, Revision, SourceDomain, SourceId, SourceIdentity, VerifiedAuthContext,
    };

    use super::{
        RepositoryError, RepositoryPort, SourceRepositoryPort, VerifiedOwnerScope, advance_revision,
    };

    #[derive(Clone, Debug, Eq, PartialEq)]
    struct SyntheticRecord {
        owner: crate::identity::OwnerId,
        source: SourceIdentity,
        revision: Revision,
        correlation: CorrelationId,
        value: &'static str,
    }

    #[derive(Default)]
    struct SyntheticRepository {
        records: Mutex<HashMap<SourceId, SyntheticRecord>>,
    }

    struct SyntheticCreate {
        correlation: CorrelationId,
        value: &'static str,
    }

    impl RepositoryPort for SyntheticRepository {
        type Store = crate::storage::ConversationStore;
        type Key = SourceId;
        type Record = SyntheticRecord;

        fn read_for_owner(
            &self,
            owner: VerifiedOwnerScope<'_>,
            source_id: Self::Key,
        ) -> impl Future<Output = Result<Self::Record, RepositoryError>> + Send {
            let result = self
                .records
                .lock()
                .map_err(|_| RepositoryError::BackendFailure)
                .and_then(|records| {
                    records
                        .get(&source_id)
                        .ok_or(RepositoryError::NotFound)
                        .and_then(|record| {
                            owner.ensure_record_owner(record.owner)?;
                            Ok(record.clone())
                        })
                });
            std::future::ready(result)
        }
    }

    impl SourceRepositoryPort for SyntheticRepository {
        type CreateCommand = SyntheticCreate;
        type UpdateCommand = &'static str;

        fn create_for_owner(
            &self,
            owner: VerifiedOwnerScope<'_>,
            command: Self::CreateCommand,
        ) -> impl Future<Output = Result<Self::Record, RepositoryError>> + Send {
            let source = SourceIdentity::new(SourceDomain::Conversation);
            let record = SyntheticRecord {
                owner: owner.owner_id(),
                source,
                revision: Revision::INITIAL,
                correlation: command.correlation,
                value: command.value,
            };
            let result = self
                .records
                .lock()
                .map_err(|_| RepositoryError::BackendFailure)
                .map(|mut records| {
                    records.insert(source.id(), record.clone());
                    record
                });
            std::future::ready(result)
        }

        fn revise_for_owner(
            &self,
            owner: VerifiedOwnerScope<'_>,
            source_id: Self::Key,
            expected: Revision,
            value: Self::UpdateCommand,
        ) -> impl Future<Output = Result<Self::Record, RepositoryError>> + Send {
            let result = self
                .records
                .lock()
                .map_err(|_| RepositoryError::BackendFailure)
                .and_then(|mut records| {
                    records
                        .get_mut(&source_id)
                        .ok_or(RepositoryError::NotFound)
                        .and_then(|record| {
                            owner.ensure_record_owner(record.owner)?;
                            record.revision = advance_revision(record.revision, expected)?;
                            record.value = value;
                            Ok(record.clone())
                        })
                });
            std::future::ready(result)
        }
    }

    #[tokio::test]
    async fn synthetic_contract_fails_closed_across_owners() {
        let owner = VerifiedAuthContext::synthetic(1);
        let other_owner = VerifiedAuthContext::synthetic(2);
        let repository = Arc::new(SyntheticRepository::default());
        let owner_repository = repository.scope(&owner);
        assert_eq!(
            owner_repository.store_kind(),
            crate::storage::StoreKind::Conversation
        );
        assert_eq!(owner_repository.source_domain(), SourceDomain::Conversation);
        let created = repository
            .scope(&owner)
            .create(SyntheticCreate {
                correlation: CorrelationId::new(),
                value: "private",
            })
            .await
            .expect("owner can create");

        assert_eq!(
            repository
                .scope(&other_owner)
                .read(created.source.id())
                .await,
            Err(RepositoryError::NotFound)
        );
        assert_eq!(
            repository
                .scope(&other_owner)
                .revise(created.source.id(), Revision::INITIAL, "forged",)
                .await,
            Err(RepositoryError::NotFound)
        );
        assert_eq!(
            repository
                .scope(&owner)
                .read(created.source.id())
                .await
                .expect("owner can read")
                .value,
            "private"
        );
    }

    #[tokio::test]
    async fn synthetic_contract_preserves_state_on_revision_conflict() {
        let owner = VerifiedAuthContext::synthetic(1);
        let repository = Arc::new(SyntheticRepository::default());
        let created = repository
            .scope(&owner)
            .create(SyntheticCreate {
                correlation: CorrelationId::new(),
                value: "first",
            })
            .await
            .expect("owner can create");
        let updated = repository
            .scope(&owner)
            .revise(created.source.id(), Revision::INITIAL, "second")
            .await
            .expect("first revision should advance");

        assert_eq!(
            repository
                .scope(&owner)
                .revise(created.source.id(), Revision::INITIAL, "stale",)
                .await,
            Err(RepositoryError::RevisionConflict {
                expected: Revision::INITIAL,
                actual: updated.revision,
            })
        );
        let current = repository
            .scope(&owner)
            .read(created.source.id())
            .await
            .expect("record remains readable");
        assert_eq!(current.value, "second");
        assert_eq!(current.revision, updated.revision);
    }
}
