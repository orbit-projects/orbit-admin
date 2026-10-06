# Copyright 2026-present Orbit Contributors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Bounded, payload-free audit records owned by the optional Admin package."""

from __future__ import annotations

import asyncio
from collections import deque
from datetime import UTC, datetime
from threading import RLock
from typing import Protocol, runtime_checkable
from uuid import UUID, uuid4

from orbit._limits import is_aware_datetime
from orbit.security.context import current_principal
from orbit_auth import Principal
from orbit_sql import SQLDatabase
from pydantic import BaseModel, ConfigDict, Field, StrictBool, StrictStr, field_validator


class AdminAuditRecord(BaseModel):
    """One immutable, payload-free Admin operation result."""

    model_config = ConfigDict(frozen=True, extra="forbid", validate_default=True)

    id: UUID = Field(default_factory=uuid4)
    action: StrictStr = Field(pattern=r"^[a-z][a-z0-9.-]{0,62}$")
    target: StrictStr = Field(default="", max_length=255)
    subject: StrictStr = Field(default="anonymous", max_length=255)
    provider: StrictStr = Field(default="", max_length=63)
    success: StrictBool
    error_code: StrictStr | None = Field(
        default=None,
        max_length=127,
        pattern=r"^[A-Za-z][A-Za-z0-9_.-]{0,126}$",
    )
    occurred_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    @field_validator("target", "subject", "provider")
    @classmethod
    def validate_text_fields(cls, value: str) -> str:
        """Reject control characters before text reaches operator-facing output."""
        if any(ord(character) < 32 or ord(character) == 127 for character in value):
            raise ValueError("Audit text fields cannot contain control characters.")
        return value

    @field_validator("occurred_at")
    @classmethod
    def require_aware_timestamp(cls, value: datetime) -> datetime:
        """Keep event chronology unambiguous across processes and time zones."""
        if not is_aware_datetime(value):
            raise ValueError("Audit timestamps must include timezone information.")
        return value


@runtime_checkable
class AdminAuditSink(Protocol):
    """Asynchronous destination for payload-free Admin mutation outcomes."""

    async def record(
        self,
        action: str,
        *,
        target: str = "",
        success: bool,
        error_code: str | None = None,
    ) -> AdminAuditRecord:
        """Persist or retain one validated audit record."""


class AdminAuditLog:
    """Thread-safe bounded process-local audit history for one Admin plugin instance.

    Records never retain request bodies, entity values, or resource keys. This history is not
    durable and is not shared between worker processes; production deployments that require
    durable audit must inject a separately reviewed audit sink before enabling mutations.
    """

    def __init__(self, *, capacity: int = 1_000) -> None:
        if (
            isinstance(capacity, bool)
            or not isinstance(capacity, int)
            or not 1 <= capacity <= 100_000
        ):
            raise ValueError("Audit capacity must be an integer from 1 through 100,000.")
        self._records: deque[AdminAuditRecord] = deque(maxlen=capacity)
        self._lock = RLock()

    @property
    def records(self) -> tuple[AdminAuditRecord, ...]:
        """Return an immutable chronological snapshot of retained records."""
        with self._lock:
            return tuple(record.model_copy(deep=True) for record in self._records)

    async def recent(self, *, limit: int = 100) -> tuple[AdminAuditRecord, ...]:
        """Return a bounded newest-first audit snapshot for the protected operator view."""
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 1_000:
            raise ValueError("limit must be an integer from 1 through 1,000.")
        with self._lock:
            return tuple(record.model_copy(deep=True) for record in reversed(self._records))[:limit]

    async def record(
        self,
        action: str,
        *,
        target: str = "",
        success: bool,
        error_code: str | None = None,
    ) -> AdminAuditRecord:
        """Append one validated record without retaining request or entity payloads."""
        principal = current_principal()
        identity = principal.identity if isinstance(principal, Principal) else None
        record = AdminAuditRecord(
            action=action,
            target=target,
            subject=(
                identity.subject
                if identity is not None
                else ("authenticated" if principal is not None else "anonymous")
            ),
            provider=identity.provider if identity is not None else "",
            success=success,
            error_code=error_code,
        )
        with self._lock:
            self._records.append(record)
        return record


class SQLAdminAuditLog:
    """Durable, bounded audit sink using an application-owned Orbit SQL database.

    The database lifecycle remains owned by the application. Records are inserted and retention
    pruning runs in one database transaction. The sink does not make a resource mutation and its
    audit entry atomic unless the resource repository participates in that same transaction.
    """

    _TABLE = "orbit_admin_audit_log"
    _MAX_RECORDS = 10_000_000

    def __init__(self, database: SQLDatabase, *, max_records: int = 1_000_000) -> None:
        """Bind a SQL capability without taking ownership of its connection lifecycle."""
        if not isinstance(database, SQLDatabase):
            raise TypeError("database must implement the orbit-sql SQLDatabase contract.")
        if (
            isinstance(max_records, bool)
            or not isinstance(max_records, int)
            or not 1 <= max_records <= self._MAX_RECORDS
        ):
            raise ValueError("max_records must be an integer from 1 through 10,000,000.")
        self._database = database
        self._max_records = max_records
        self._initialized = False
        self._initialize_lock = asyncio.Lock()

    async def initialize(self) -> None:
        """Create the fixed, namespaced table before the sink is used."""
        if self._initialized:
            return
        async with self._initialize_lock:
            if self._initialized:
                return
            try:
                await self._database.execute(
                    "CREATE TABLE IF NOT EXISTS orbit_admin_audit_log ("
                    "id CHAR(36) PRIMARY KEY, "
                    "action VARCHAR(63) NOT NULL, "
                    "target VARCHAR(255) NOT NULL, "
                    "subject VARCHAR(255) NOT NULL, "
                    "provider VARCHAR(63) NOT NULL, "
                    "success BOOLEAN NOT NULL, "
                    "error_code VARCHAR(127), "
                    "occurred_at VARCHAR(40) NOT NULL)"
                )
            except asyncio.CancelledError:
                raise
            except Exception:
                raise RuntimeError("Admin SQL audit table initialization failed.") from None
            self._initialized = True

    async def record(
        self,
        action: str,
        *,
        target: str = "",
        success: bool,
        error_code: str | None = None,
    ) -> AdminAuditRecord:
        """Write one redacted audit result and enforce the configured retention ceiling."""
        await self.initialize()
        principal = current_principal()
        identity = principal.identity if isinstance(principal, Principal) else None
        record = AdminAuditRecord(
            action=action,
            target=target,
            subject=(
                identity.subject
                if identity is not None
                else ("authenticated" if principal is not None else "anonymous")
            ),
            provider=identity.provider if identity is not None else "",
            success=success,
            error_code=error_code,
        )
        try:
            async with self._database.transaction() as transaction:
                await transaction.execute(
                    "INSERT INTO orbit_admin_audit_log "
                    "(id, action, target, subject, provider, success, error_code, occurred_at) "
                    "VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
                    (
                        str(record.id),
                        record.action,
                        record.target,
                        record.subject,
                        record.provider,
                        record.success,
                        record.error_code,
                        record.occurred_at.isoformat(),
                    ),
                )
                count = await transaction.fetch_one(
                    "SELECT COUNT(*) AS record_count FROM orbit_admin_audit_log"
                )
                if count is None:
                    raise RuntimeError("Audit row count query returned no row.")
                record_count = count["record_count"]
                if isinstance(record_count, bool) or not isinstance(record_count, int):
                    raise RuntimeError("Audit row count query returned invalid data.")
                excess = record_count - self._max_records
                if excess > 0:
                    await transaction.execute(
                        "DELETE FROM orbit_admin_audit_log WHERE id IN ("
                        "SELECT id FROM (SELECT id FROM orbit_admin_audit_log "
                        "ORDER BY occurred_at ASC, id ASC LIMIT $1) AS expired_records)",
                        (excess,),
                    )
        except asyncio.CancelledError:
            raise
        except Exception:
            raise RuntimeError("Admin SQL audit write failed.") from None
        return record

    async def recent(self, *, limit: int = 100) -> tuple[AdminAuditRecord, ...]:
        """Return a bounded newest-first page without exposing an unbounded table scan."""
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 1_000:
            raise ValueError("limit must be an integer from 1 through 1,000.")
        await self.initialize()
        try:
            rows = await self._database.fetch_all(
                "SELECT id, action, target, subject, provider, success, error_code, occurred_at "
                "FROM orbit_admin_audit_log ORDER BY occurred_at DESC, id DESC LIMIT $1",
                (limit,),
                limit=limit,
            )
        except asyncio.CancelledError:
            raise
        except Exception:
            raise RuntimeError("Admin SQL audit read failed.") from None
        records: list[AdminAuditRecord] = []
        for row in rows:
            identifier = row["id"]
            action = row["action"]
            target = row["target"]
            subject = row["subject"]
            provider = row["provider"]
            success = row["success"]
            error_code = row["error_code"]
            occurred_at = row["occurred_at"]
            if (
                not isinstance(identifier, str)
                or not isinstance(action, str)
                or not isinstance(target, str)
                or not isinstance(subject, str)
                or not isinstance(provider, str)
                or (error_code is not None and not isinstance(error_code, str))
                or not isinstance(occurred_at, str)
                or success not in (True, False, 0, 1)
            ):
                raise RuntimeError("Admin SQL audit read returned invalid data.")
            try:
                records.append(
                    AdminAuditRecord(
                        id=UUID(identifier),
                        action=action,
                        target=target,
                        subject=subject,
                        provider=provider,
                        success=bool(success),
                        error_code=error_code,
                        occurred_at=datetime.fromisoformat(occurred_at),
                    )
                )
            except (TypeError, ValueError):
                raise RuntimeError("Admin SQL audit read returned invalid data.") from None
        return tuple(records)


__all__ = ["AdminAuditLog", "AdminAuditRecord", "AdminAuditSink", "SQLAdminAuditLog"]
