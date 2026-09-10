"""Small, explicit schema-version mechanism for the local SQLite database.

Version 1 is the first persisted audit/STIG schema.  Future releases should add
ordered migration functions here rather than silently mutating existing user
databases through ``create_all``.
"""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import Engine, inspect, select

from stig_audit_pro.infrastructure.persistence.db_models import Base, SchemaVersion

CURRENT_SCHEMA_VERSION = 2


class UnsupportedSchemaVersion(RuntimeError):
    """Raised when a database was created by a newer application version."""


def get_schema_version(engine: Engine) -> int:
    """Return the application's schema version, or zero for an empty database."""

    if not inspect(engine).has_table(SchemaVersion.__tablename__):
        return 0
    with engine.connect() as connection:
        value = connection.scalar(
            select(SchemaVersion.version).where(SchemaVersion.id == 1)
        )
    return int(value or 0)


def initialize_schema(engine: Engine) -> int:
    """Create or migrate the schema and return its resulting version."""

    existing_version = get_schema_version(engine)
    if existing_version > CURRENT_SCHEMA_VERSION:
        raise UnsupportedSchemaVersion(
            "Database schema version "
            f"{existing_version} is newer than supported version "
            f"{CURRENT_SCHEMA_VERSION}."
        )

    # Version 2 adds the local activity trail. create_all is safe for this
    # additive migration and preserves every existing v1 table and row.
    Base.metadata.create_all(engine)
    with engine.begin() as connection:
        version = connection.scalar(
            select(SchemaVersion.version).where(SchemaVersion.id == 1)
        )
        if version is None:
            connection.execute(
                SchemaVersion.__table__.insert().values(
                    id=1,
                    version=CURRENT_SCHEMA_VERSION,
                    applied_at=datetime.now(timezone.utc),
                )
            )
        elif int(version) < CURRENT_SCHEMA_VERSION:
            # Reserved for ordered migrations in future releases.
            connection.execute(
                SchemaVersion.__table__.update()
                .where(SchemaVersion.id == 1)
                .values(
                    version=CURRENT_SCHEMA_VERSION,
                    applied_at=datetime.now(timezone.utc),
                )
            )
        connection.exec_driver_sql(f"PRAGMA user_version = {CURRENT_SCHEMA_VERSION}")
    return CURRENT_SCHEMA_VERSION
