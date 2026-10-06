"""Durable Admin audit behavior against Orbit's real local SQL provider."""

from __future__ import annotations

import asyncio

import pytest
from orbit_sql_sqlite import SQLiteDatabase

from orbit_admin.audit import SQLAdminAuditLog


@pytest.mark.asyncio
async def test_sql_audit_sink_persists_redacted_records_and_bounds_retention() -> None:
    database = SQLiteDatabase(":memory:")
    audit = SQLAdminAuditLog(database, max_records=2)
    try:
        await audit.record("crud.create", target="accounts", success=True)
        await audit.record(
            "crud.update", target="accounts", success=False, error_code="admin.conflict"
        )
        await audit.record("crud.delete", target="accounts", success=True)

        records = await audit.recent(limit=2)

        assert [record.action for record in records] == ["crud.delete", "crud.update"]
        assert all(record.subject == "anonymous" for record in records)
        assert len(await audit.recent(limit=1)) == 1
        with pytest.raises(ValueError, match="limit"):
            await audit.recent(limit=1_001)
    finally:
        await database.aclose()


@pytest.mark.asyncio
async def test_sql_audit_sink_rejects_invalid_retention_limits() -> None:
    database = SQLiteDatabase(":memory:")
    try:
        with pytest.raises(ValueError, match="max_records"):
            SQLAdminAuditLog(database, max_records=True)
    finally:
        await database.aclose()


@pytest.mark.asyncio
async def test_sql_audit_sink_serializes_concurrent_writes_within_retention() -> None:
    database = SQLiteDatabase(":memory:")
    audit = SQLAdminAuditLog(database, max_records=3)
    try:
        await asyncio.gather(
            *(
                audit.record("crud.create", target=f"resource-{index}", success=True)
                for index in range(8)
            )
        )

        records = await audit.recent(limit=3)

        assert len(records) == 3
        assert len({record.id for record in records}) == 3
    finally:
        await database.aclose()
