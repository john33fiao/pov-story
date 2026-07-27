CREATE TABLE _pov_store_contract (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    store_kind TEXT NOT NULL CHECK (store_kind = 'calendar'),
    migration_namespace TEXT NOT NULL CHECK (migration_namespace = 'sqlite/calendar')
) STRICT;

INSERT INTO _pov_store_contract(singleton, store_kind, migration_namespace)
VALUES (1, 'calendar', 'sqlite/calendar');
