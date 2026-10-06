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
"""Typed remote administrative client over an injectable HTTP transport.

Synchronous transports run in bounded, detached daemon threads. Async transports are also bounded
at the operation boundary: a cancellation-resistant call is detached and retained per operation
until it returns, preventing repeated timeouts from creating unbounded orphan work.
"""

from __future__ import annotations

import asyncio
import inspect
import re
import threading
from collections.abc import Awaitable, Mapping
from typing import Any, Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict, Field, StrictInt, field_validator

from orbit_admin._safety import (
    MAX_ADMIN_OPERATIONS,
    freeze_mapping,
    is_finite_number,
    validate_mapping,
)

_ERROR_CODE_PATTERN = re.compile(r"[a-z][a-z0-9.-]{0,126}")


class AdminHTTPResponse(BaseModel):
    """Transport-neutral response returned by an admin HTTP adapter.

    The response is a detached snapshot. Core validates the top-level JSON object and
    recursively freezes its values so an adapter cannot mutate a response after returning
    it, and a caller cannot mutate an object retained by the adapter.
    """

    model_config = ConfigDict(frozen=True, extra="forbid", validate_default=True)

    status: StrictInt = Field(ge=200, le=599)
    body: dict[str, Any] = Field(default_factory=dict)

    @field_validator("body", mode="before")
    @classmethod
    def validate_body(cls, value: object) -> dict[str, Any]:
        """Reject non-string JSON keys before Pydantic can coerce remote data."""
        if not isinstance(value, Mapping):
            raise TypeError("Admin response bodies must be mappings.")
        # Validate while copying so a custom adapter mapping cannot be fully materialized before
        # the shared cardinality and key-shape limits are applied.
        return validate_mapping(value, name="Admin response body")

    def model_post_init(self, __context: object) -> None:
        """Protect nested response data while retaining JSON-compatible serialization."""
        object.__setattr__(self, "body", freeze_mapping(self.body))


@runtime_checkable
class AdminTransport(Protocol):
    """HTTP adapter boundary; concrete clients own TLS, pooling and proxy policy."""

    def request(
        self,
        method: str,
        path: str,
        *,
        headers: Mapping[str, str],
        body: Mapping[str, Any] | None = None,
    ) -> AdminHTTPResponse | Awaitable[AdminHTTPResponse]:
        """Perform one request and return a detached structured response."""


class AdminClientError(RuntimeError):
    """Safe remote admin failure retaining status and server error code only."""

    def __init__(self, status: int, code: str) -> None:
        """Create a bounded error that cannot inject arbitrary remote response text."""
        if isinstance(status, bool) or not isinstance(status, int) or not 300 <= status <= 599:
            raise ValueError("Admin error status must be an integer from 300 through 599.")
        if not isinstance(code, str) or _ERROR_CODE_PATTERN.fullmatch(code) is None:
            raise ValueError("Admin error codes must be lowercase identifier-shaped strings.")
        self.status = status
        self.code = code
        super().__init__(f"Admin request failed ({status}): {code}")


class AdminClient:
    """Authenticated client for Core inspection and explicitly authorized operations.

    The client binds to the event loop used by its first request. Keep one instance per
    application event loop; using it from another loop raises ``RuntimeError`` rather than
    relying on asyncio primitive behavior that can vary with contention.
    """

    def __init__(
        self,
        transport: AdminTransport,
        *,
        token: str,
        timeout: float = 10,
        max_sync_workers: int = 4,
        max_async_operations: int = 1_000,
    ) -> None:
        if (
            not isinstance(token, str)
            or not token
            or len(token) > 16_384
            or any(
                character.isspace() or ord(character) < 32 or ord(character) == 127
                for character in token
            )
        ):
            raise ValueError("token must be a nonempty credential without whitespace.")
        if (
            isinstance(timeout, bool)
            or not isinstance(timeout, (int, float))
            or not is_finite_number(timeout)
            or timeout <= 0
        ):
            raise ValueError("timeout must be positive.")
        if (
            isinstance(max_sync_workers, bool)
            or not isinstance(max_sync_workers, int)
            or not 1 <= max_sync_workers <= MAX_ADMIN_OPERATIONS
        ):
            raise ValueError("max_sync_workers must be positive and no more than 1,000,000.")
        if (
            isinstance(max_async_operations, bool)
            or not isinstance(max_async_operations, int)
            or not 1 <= max_async_operations <= MAX_ADMIN_OPERATIONS
        ):
            raise ValueError("max_async_operations must be positive and no more than 1,000,000.")
        if not callable(getattr(transport, "request", None)):
            raise TypeError("Admin transport must provide a callable request method.")
        self._transport = transport
        self._headers = {"authorization": f"Bearer {token}", "accept": "application/json"}
        self._timeout = timeout
        self._sync_slots = asyncio.Semaphore(max_sync_workers)
        self._async_slots = asyncio.Semaphore(max_async_operations)
        self._detached_async: dict[tuple[str, str], asyncio.Future[AdminHTTPResponse]] = {}
        self._event_loop: asyncio.AbstractEventLoop | None = None
        self._event_loop_lock = threading.Lock()

    async def inspect(self, section: str) -> Mapping[str, Any]:
        """Fetch one allowlisted inspection section."""
        if not isinstance(section, str) or section not in {
            "lifecycle",
            "audit",
            "health",
            "diagnostics",
            "state",
            "config",
            "services",
            "plugins",
            "routes",
            "dependencies",
            "events",
            "tasks",
        }:
            raise ValueError("Unknown admin inspection section.")
        return await self._request("GET", f"/admin/{section}")

    async def service_action(self, name: str, action: str) -> Mapping[str, Any]:
        """Start, stop, or restart a named service."""
        return await self._mutate(
            "/admin/services", name, action, {"start", "stop", "restart", "reload"}
        )

    async def restart_task(self, name: str) -> Mapping[str, Any]:
        """Restart one supervised task."""
        return await self._mutate("/admin/tasks", name, "restart", {"restart"})

    async def refresh_health(self) -> Mapping[str, Any]:
        """Request an authenticated health refresh."""
        return await self._request("POST", "/admin/health/refresh", body={})

    async def _mutate(
        self, prefix: str, name: str, action: str, allowed: set[str]
    ) -> Mapping[str, Any]:
        if (
            not isinstance(name, str)
            or re.fullmatch(r"[a-z][a-z0-9-]{0,62}", name) is None
            or not isinstance(action, str)
            or action not in allowed
        ):
            raise ValueError("Invalid administrative operation.")
        return await self._request("POST", f"{prefix}/{name}/{action}", body={})

    async def _request(
        self, method: str, path: str, *, body: Mapping[str, Any] | None = None
    ) -> Mapping[str, Any]:
        self._bind_event_loop()
        request = self._transport.request
        headers = dict(self._headers)
        result: AdminHTTPResponse | Awaitable[AdminHTTPResponse]
        operation = (method, path)
        self._reject_pending_async(operation)
        async_request = inspect.iscoroutinefunction(request) or (
            callable(request) and inspect.iscoroutinefunction(type(request).__call__)
        )
        async_slot_acquired = False
        if async_request:
            # Retain the slot until the adapter task finishes, including when the caller
            # times out. This bounds distinct late async operations, not only repeated calls
            # to the same path.
            await asyncio.wait_for(self._async_slots.acquire(), timeout=self._timeout)
            async_slot_acquired = True
            try:
                result = request(method, path, headers=headers, body=body)
            except BaseException:
                self._async_slots.release()
                raise
        else:
            # A synchronous adapter must never block the caller's event loop. The timeout
            # also bounds DNS, connection setup and response acquisition inside that adapter.
            # Keep the semaphore held after a timeout until the detached worker exits; releasing
            # it when the caller stops waiting would permit one permanently blocked thread per
            # request. Waiting for a slot is bounded as well, so a saturated adapter fails fast.
            await asyncio.wait_for(self._sync_slots.acquire(), timeout=self._timeout)
            loop = asyncio.get_running_loop()
            pending: asyncio.Future[AdminHTTPResponse | Awaitable[AdminHTTPResponse]] = (
                loop.create_future()
            )

            def notify(callback: Any, *arguments: Any) -> None:
                """Notify the event loop without leaking errors after loop shutdown."""
                try:
                    loop.call_soon_threadsafe(callback, *arguments)
                except RuntimeError:
                    # A daemon transport thread may outlive a cancelled test loop or process
                    # shutdown. There is no future or semaphore left to update in that case.
                    return

            def release_slot() -> None:
                """Release the slot only after the synchronous transport has returned."""
                self._sync_slots.release()

            def set_result(value: AdminHTTPResponse | Awaitable[AdminHTTPResponse]) -> None:
                """Complete the pending response unless the caller already timed out."""
                if not pending.done():
                    pending.set_result(value)

            def set_exception(exc: BaseException) -> None:
                """Propagate transport failures while the caller is still waiting."""
                if not pending.done():
                    pending.set_exception(exc)

            def invoke() -> None:
                """Run a synchronous transport outside the event-loop thread."""
                try:
                    value = request(method, path, headers=headers, body=body)
                except BaseException as exc:
                    notify(set_exception, exc)
                else:
                    notify(set_result, value)
                finally:
                    notify(release_slot)

            try:
                threading.Thread(target=invoke, name="orbit-admin-transport", daemon=True).start()
            except BaseException:
                self._sync_slots.release()
                raise
            async with asyncio.timeout(self._timeout):
                result = await pending
        if inspect.isawaitable(result):
            if not async_slot_acquired:
                try:
                    await asyncio.wait_for(self._async_slots.acquire(), timeout=self._timeout)
                except BaseException:
                    close = getattr(result, "close", None)
                    if callable(close):
                        close()
                    raise
                async_slot_acquired = True
            response = await self._await_async_result(
                result, operation, async_slot_acquired=async_slot_acquired
            )
        else:
            if async_slot_acquired:
                self._async_slots.release()
            response = result
        if not isinstance(response, AdminHTTPResponse):
            raise TypeError("Admin transports must return AdminHTTPResponse.")
        if not 200 <= response.status < 300:
            raw_code = response.body.get("code")
            code = (
                raw_code
                if isinstance(raw_code, str) and _ERROR_CODE_PATTERN.fullmatch(raw_code)
                else (
                    "admin.unexpected-status" if response.status < 400 else "admin.remote-failure"
                )
            )
            raise AdminClientError(response.status, code)
        return dict(response.body)

    def _bind_event_loop(self) -> None:
        """Bind this client's asyncio resources to the first request's running loop."""
        current_loop = asyncio.get_running_loop()
        with self._event_loop_lock:
            if self._event_loop is None:
                self._event_loop = current_loop
            elif self._event_loop is not current_loop:
                raise RuntimeError(
                    "AdminClient instances may only be used from the event loop of their first "
                    "request."
                )

    def _reject_pending_async(self, operation: tuple[str, str]) -> None:
        """Fail closed while one cancellation-resistant operation is still unwinding."""
        pending = self._detached_async.get(operation)
        if pending is None:
            return
        if pending.done():
            self._retire_async(operation, pending)
            return
        raise TimeoutError("An earlier admin transport operation is still cancelling.")

    async def _await_async_result(
        self,
        result: Awaitable[AdminHTTPResponse],
        operation: tuple[str, str],
        *,
        async_slot_acquired: bool,
    ) -> AdminHTTPResponse:
        """Await one async adapter under a deadline while retaining late cancellation results."""
        try:
            task = asyncio.ensure_future(result)
        except BaseException:
            if async_slot_acquired:
                self._async_slots.release()
            raise
        if async_slot_acquired:
            task.add_done_callback(self._release_async_slot)
        try:
            done, _ = await asyncio.wait({task}, timeout=self._timeout)
        except asyncio.CancelledError:
            if task.done():
                self._retire_async(operation, task)
            else:
                self._detach_async(operation, task)
            raise
        if not done:
            self._detach_async(operation, task)
            raise TimeoutError("Admin transport request exceeded its deadline.")
        try:
            response = task.result()
        except BaseException:
            self._detached_async.pop(operation, None)
            raise
        self._detached_async.pop(operation, None)
        return response

    def _release_async_slot(self, task: asyncio.Future[AdminHTTPResponse]) -> None:
        """Release an async transport slot after the adapter task has actually finished."""
        self._async_slots.release()

    def _detach_async(
        self,
        operation: tuple[str, str],
        task: asyncio.Future[AdminHTTPResponse],
    ) -> None:
        """Retain one late async adapter result and request its cancellation."""
        self._detached_async[operation] = task
        task.cancel()
        task.add_done_callback(lambda finished: self._retire_async(operation, finished))

    def _retire_async(
        self,
        operation: tuple[str, str],
        task: asyncio.Future[AdminHTTPResponse],
    ) -> None:
        """Forget detached adapter work and consume its eventual result or exception."""
        if self._detached_async.get(operation) is task:
            del self._detached_async[operation]
        try:
            task.exception()
        except (asyncio.CancelledError, Exception):
            return


__all__ = ["AdminClient", "AdminClientError", "AdminHTTPResponse", "AdminTransport"]
