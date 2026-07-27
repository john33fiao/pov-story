use crate::storage::{StoreKind, StoreRole};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PostgresAdapterStatus {
    NotImplemented,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PostgresBoundary {
    pub kind: StoreKind,
    pub role: StoreRole,
    pub migration_namespace: &'static str,
    pub migration_sql: Option<&'static str>,
    pub status: PostgresAdapterStatus,
}

#[must_use]
pub const fn boundary(kind: StoreKind) -> PostgresBoundary {
    let migration_namespace = match kind {
        StoreKind::Conversation => "postgres/conversation",
        StoreKind::Knowledge => "postgres/knowledge",
        StoreKind::Calendar => "postgres/calendar",
        StoreKind::Embedding => "postgres/embedding",
    };

    PostgresBoundary {
        kind,
        role: StoreRole::for_kind(kind),
        migration_namespace,
        migration_sql: None,
        status: PostgresAdapterStatus::NotImplemented,
    }
}
