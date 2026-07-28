use std::{fmt, num::NonZeroU64};

use uuid::Uuid;

macro_rules! public_id {
    ($name:ident) => {
        #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(Uuid);

        impl $name {
            #[must_use]
            pub fn new() -> Self {
                Self(Uuid::new_v4())
            }

            #[must_use]
            pub const fn from_uuid(value: Uuid) -> Option<Self> {
                if matches!(value.get_version(), Some(uuid::Version::Random))
                    && matches!(value.get_variant(), uuid::Variant::RFC4122)
                {
                    Some(Self(value))
                } else {
                    None
                }
            }

            #[must_use]
            pub const fn as_uuid(self) -> Uuid {
                self.0
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(formatter)
            }
        }
    };
}

public_id!(SourceId);
public_id!(CorrelationId);

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct OwnerId(Uuid);

impl OwnerId {
    pub(crate) const fn from_verified_uuid(value: Uuid) -> Self {
        Self(value)
    }

    #[cfg(test)]
    pub(crate) const fn synthetic(value: u128) -> Self {
        Self(Uuid::from_u128(value))
    }

    #[must_use]
    pub const fn as_uuid(self) -> Uuid {
        self.0
    }
}

impl fmt::Display for OwnerId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

/// An owner scope minted only after an authentication boundary verifies a subject.
///
/// No production constructor exists until the trusted authentication integration
/// is implemented. Transport input can carry record identifiers, but it cannot
/// create the capability repositories require for owner authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedAuthContext {
    owner_id: OwnerId,
}

impl VerifiedAuthContext {
    pub(crate) const fn from_verified_owner(owner_id: OwnerId) -> Self {
        Self { owner_id }
    }

    #[cfg(test)]
    pub(crate) const fn synthetic(owner: u128) -> Self {
        Self::from_verified_owner(OwnerId::synthetic(owner))
    }

    #[must_use]
    pub const fn owner_id(&self) -> OwnerId {
        self.owner_id
    }

    #[must_use]
    pub const fn bind_source(&self, source: SourceIdentity, revision: Revision) -> SourceRevision {
        SourceRevision {
            owner_id: self.owner_id,
            source,
            revision,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum SourceDomain {
    Conversation,
    Knowledge,
    Calendar,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct SourceIdentity {
    domain: SourceDomain,
    id: SourceId,
}

impl SourceIdentity {
    #[must_use]
    pub fn new(domain: SourceDomain) -> Self {
        Self {
            domain,
            id: SourceId::new(),
        }
    }

    #[must_use]
    pub const fn from_parts(domain: SourceDomain, id: SourceId) -> Self {
        Self { domain, id }
    }

    #[must_use]
    pub const fn domain(self) -> SourceDomain {
        self.domain
    }

    #[must_use]
    pub const fn id(self) -> SourceId {
        self.id
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Revision(NonZeroU64);

impl Revision {
    pub const INITIAL: Self = Self(NonZeroU64::MIN);
    pub const MAX: u64 = i64::MAX as u64;

    #[must_use]
    pub const fn new(value: u64) -> Option<Self> {
        if value > Self::MAX {
            return None;
        }
        match NonZeroU64::new(value) {
            Some(value) => Some(Self(value)),
            None => None,
        }
    }

    #[must_use]
    pub const fn get(self) -> u64 {
        self.0.get()
    }

    pub(crate) fn checked_next(self) -> Option<Self> {
        self.get().checked_add(1).and_then(Self::new)
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct SourceRevision {
    owner_id: OwnerId,
    source: SourceIdentity,
    revision: Revision,
}

impl SourceRevision {
    #[must_use]
    pub const fn owner_id(self) -> OwnerId {
        self.owner_id
    }

    #[must_use]
    pub const fn source(self) -> SourceIdentity {
        self.source
    }

    #[must_use]
    pub const fn revision(self) -> Revision {
        self.revision
    }

    #[must_use]
    pub fn freshness_against(self, current: Option<Self>) -> DerivativeFreshness {
        let Some(current) = current else {
            return DerivativeFreshness::SourceMissing;
        };

        if self.owner_id != current.owner_id || self.source != current.source {
            return DerivativeFreshness::Mismatch;
        }

        if self.revision.get() == current.revision.get() {
            DerivativeFreshness::Current
        } else if self.revision.get() < current.revision.get() {
            DerivativeFreshness::Stale {
                regenerate_from: current,
            }
        } else {
            DerivativeFreshness::InvalidFuture
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DerivativeFreshness {
    Current,
    Stale { regenerate_from: SourceRevision },
    SourceMissing,
    Mismatch,
    InvalidFuture,
}

#[cfg(test)]
mod tests {
    use super::{DerivativeFreshness, Revision, SourceDomain, SourceIdentity, VerifiedAuthContext};

    #[test]
    fn derivative_freshness_is_bound_to_owner_source_and_revision() {
        let owner = VerifiedAuthContext::synthetic(1);
        let other_owner = VerifiedAuthContext::synthetic(2);
        let source = SourceIdentity::new(SourceDomain::Conversation);
        let other_source = SourceIdentity::new(SourceDomain::Conversation);
        let revision_one = Revision::INITIAL;
        let revision_two = Revision::new(2).expect("positive revision");
        let revision_three = Revision::new(3).expect("positive revision");
        let current = owner.bind_source(source, revision_two);

        assert_eq!(
            current.freshness_against(Some(current)),
            DerivativeFreshness::Current
        );
        assert_eq!(
            owner
                .bind_source(source, revision_one)
                .freshness_against(Some(current)),
            DerivativeFreshness::Stale {
                regenerate_from: current,
            }
        );
        assert_eq!(
            owner
                .bind_source(source, revision_three)
                .freshness_against(Some(current)),
            DerivativeFreshness::InvalidFuture
        );
        assert_eq!(
            other_owner
                .bind_source(source, revision_two)
                .freshness_against(Some(current)),
            DerivativeFreshness::Mismatch
        );
        assert_eq!(
            owner
                .bind_source(other_source, revision_two)
                .freshness_against(Some(current)),
            DerivativeFreshness::Mismatch
        );
        assert_eq!(
            current.freshness_against(None),
            DerivativeFreshness::SourceMissing
        );
    }
}
