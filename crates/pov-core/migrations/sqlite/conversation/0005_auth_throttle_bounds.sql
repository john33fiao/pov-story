CREATE TABLE auth_authenticator_throttles_0005_guard (
    invalid_row_count INTEGER NOT NULL CHECK (invalid_row_count = 0)
) STRICT;

INSERT INTO auth_authenticator_throttles_0005_guard(invalid_row_count)
SELECT count(*)
FROM auth_authenticator_throttles
WHERE
    failure_count NOT BETWEEN 0 AND 100
    OR CASE
        WHEN failure_count = 0 THEN
            next_allowed_at_micros <> 0
        WHEN failure_count BETWEEN 1 AND 4 THEN
            next_allowed_at_micros <> updated_at_micros
        WHEN failure_count = 5 THEN
            updated_at_micros > 9223372036824775807
            OR next_allowed_at_micros < updated_at_micros
            OR next_allowed_at_micros - updated_at_micros <> 30000000
        WHEN failure_count = 6 THEN
            updated_at_micros > 9223372036794775807
            OR next_allowed_at_micros < updated_at_micros
            OR next_allowed_at_micros - updated_at_micros <> 60000000
        WHEN failure_count = 7 THEN
            updated_at_micros > 9223372036734775807
            OR next_allowed_at_micros < updated_at_micros
            OR next_allowed_at_micros - updated_at_micros <> 120000000
        WHEN failure_count = 8 THEN
            updated_at_micros > 9223372036614775807
            OR next_allowed_at_micros < updated_at_micros
            OR next_allowed_at_micros - updated_at_micros <> 240000000
        WHEN failure_count = 9 THEN
            updated_at_micros > 9223372036374775807
            OR next_allowed_at_micros < updated_at_micros
            OR next_allowed_at_micros - updated_at_micros <> 480000000
        WHEN failure_count = 10 THEN
            updated_at_micros > 9223372035894775807
            OR next_allowed_at_micros < updated_at_micros
            OR next_allowed_at_micros - updated_at_micros <> 960000000
        WHEN failure_count = 11 THEN
            updated_at_micros > 9223372034934775807
            OR next_allowed_at_micros < updated_at_micros
            OR next_allowed_at_micros - updated_at_micros <> 1920000000
        WHEN failure_count BETWEEN 12 AND 100 THEN
            updated_at_micros > 9223372033254775807
            OR next_allowed_at_micros < updated_at_micros
            OR next_allowed_at_micros - updated_at_micros <> 3600000000
        ELSE 1
    END;

DROP TABLE auth_authenticator_throttles_0005_guard;

CREATE TRIGGER auth_authenticator_throttles_guard_insert_v2
BEFORE INSERT ON auth_authenticator_throttles
WHEN
    NEW.failure_count <> 0
    OR NEW.next_allowed_at_micros <> 0
    OR NEW.throttle_revision <> 1
BEGIN
    SELECT RAISE(ABORT, 'invalid initial authenticator throttle');
END;

CREATE TRIGGER auth_authenticator_throttles_guard_update_v2
BEFORE UPDATE ON auth_authenticator_throttles
WHEN
    NEW.owner_id <> OLD.owner_id
    OR NEW.authenticator <> OLD.authenticator
    OR NEW.throttle_revision <> OLD.throttle_revision + 1
    OR NEW.updated_at_micros < OLD.updated_at_micros
    OR NEW.failure_count NOT BETWEEN 0 AND 100
    OR CASE
        WHEN NEW.failure_count = 0 THEN
            NEW.next_allowed_at_micros <> 0
        WHEN NEW.failure_count BETWEEN 1 AND 4 THEN
            NEW.next_allowed_at_micros <> NEW.updated_at_micros
        WHEN NEW.failure_count = 5 THEN
            NEW.updated_at_micros > 9223372036824775807
            OR NEW.next_allowed_at_micros < NEW.updated_at_micros
            OR NEW.next_allowed_at_micros - NEW.updated_at_micros <> 30000000
        WHEN NEW.failure_count = 6 THEN
            NEW.updated_at_micros > 9223372036794775807
            OR NEW.next_allowed_at_micros < NEW.updated_at_micros
            OR NEW.next_allowed_at_micros - NEW.updated_at_micros <> 60000000
        WHEN NEW.failure_count = 7 THEN
            NEW.updated_at_micros > 9223372036734775807
            OR NEW.next_allowed_at_micros < NEW.updated_at_micros
            OR NEW.next_allowed_at_micros - NEW.updated_at_micros <> 120000000
        WHEN NEW.failure_count = 8 THEN
            NEW.updated_at_micros > 9223372036614775807
            OR NEW.next_allowed_at_micros < NEW.updated_at_micros
            OR NEW.next_allowed_at_micros - NEW.updated_at_micros <> 240000000
        WHEN NEW.failure_count = 9 THEN
            NEW.updated_at_micros > 9223372036374775807
            OR NEW.next_allowed_at_micros < NEW.updated_at_micros
            OR NEW.next_allowed_at_micros - NEW.updated_at_micros <> 480000000
        WHEN NEW.failure_count = 10 THEN
            NEW.updated_at_micros > 9223372035894775807
            OR NEW.next_allowed_at_micros < NEW.updated_at_micros
            OR NEW.next_allowed_at_micros - NEW.updated_at_micros <> 960000000
        WHEN NEW.failure_count = 11 THEN
            NEW.updated_at_micros > 9223372034934775807
            OR NEW.next_allowed_at_micros < NEW.updated_at_micros
            OR NEW.next_allowed_at_micros - NEW.updated_at_micros <> 1920000000
        WHEN NEW.failure_count BETWEEN 12 AND 100 THEN
            NEW.updated_at_micros > 9223372033254775807
            OR NEW.next_allowed_at_micros < NEW.updated_at_micros
            OR NEW.next_allowed_at_micros - NEW.updated_at_micros <> 3600000000
        ELSE 1
    END
    OR NOT (
        (
            NEW.failure_count = 0
            AND NEW.next_allowed_at_micros = 0
            AND (
                OLD.authenticator = 'password'
                OR NEW.updated_at_micros >= OLD.next_allowed_at_micros
            )
        )
        OR (
            OLD.failure_count < 100
            AND NEW.updated_at_micros >= OLD.next_allowed_at_micros
            AND NEW.failure_count = OLD.failure_count + 1
        )
        OR (
            OLD.authenticator = 'recovery'
            AND OLD.failure_count = 100
            AND NEW.failure_count = 100
            AND NEW.updated_at_micros >= OLD.next_allowed_at_micros
            AND NEW.next_allowed_at_micros > OLD.next_allowed_at_micros
        )
    )
BEGIN
    SELECT RAISE(ABORT, 'invalid bounded authenticator throttle transition');
END;

DROP TRIGGER auth_authenticator_throttles_guard_update;
