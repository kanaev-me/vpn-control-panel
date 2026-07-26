#!/usr/bin/env python3
"""Thread-safe in-memory throttling for the public login endpoint."""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from ipaddress import ip_address
from threading import Lock
from typing import Any


DEFAULT_MAX_FAILURES = 8
DEFAULT_WINDOW_SECONDS = 10 * 60
DEFAULT_BLOCK_SECONDS = 15 * 60
DEFAULT_MAX_SOURCES = 4096


@dataclass
class _SourceState:
    failures: deque[int] = field(default_factory=deque)
    blocked_until: int = 0
    last_seen: int = 0


class LoginThrottle:
    """Bound failed logins per source without affecting valid parallel sessions."""

    def __init__(
        self,
        *,
        max_failures: int = DEFAULT_MAX_FAILURES,
        window_seconds: int = DEFAULT_WINDOW_SECONDS,
        block_seconds: int = DEFAULT_BLOCK_SECONDS,
        max_sources: int = DEFAULT_MAX_SOURCES,
    ) -> None:
        if min(max_failures, window_seconds, block_seconds, max_sources) <= 0:
            raise ValueError("login throttle limits must be positive")
        self.max_failures = int(max_failures)
        self.window_seconds = int(window_seconds)
        self.block_seconds = int(block_seconds)
        self.max_sources = int(max_sources)
        self._states: dict[str, _SourceState] = {}
        self._lock = Lock()

    def _trim_failures(self, state: _SourceState, now: int) -> None:
        cutoff = now - self.window_seconds
        while state.failures and state.failures[0] <= cutoff:
            state.failures.popleft()

    def _retry_after_locked(self, source: str, now: int) -> int:
        state = self._states.get(source)
        if state is None:
            return 0
        state.last_seen = now
        self._trim_failures(state, now)
        if state.blocked_until > now:
            return state.blocked_until - now
        if state.blocked_until:
            state.blocked_until = 0
            state.failures.clear()
        if not state.failures:
            self._states.pop(source, None)
        return 0

    def retry_after(self, source: str, *, now: int) -> int:
        source = str(source or "unknown")
        with self._lock:
            return self._retry_after_locked(source, int(now))

    def record_failure(self, source: str, *, now: int) -> int:
        source = str(source or "unknown")
        now = int(now)
        with self._lock:
            retry = self._retry_after_locked(source, now)
            if retry:
                return retry

            state = self._states.setdefault(source, _SourceState())
            state.last_seen = now
            self._trim_failures(state, now)
            state.failures.append(now)

            if len(state.failures) >= self.max_failures:
                state.failures.clear()
                state.blocked_until = now + self.block_seconds
                retry = self.block_seconds
            else:
                retry = 0

            self._evict_if_needed()
            return retry

    def record_success(self, source: str) -> None:
        source = str(source or "unknown")
        with self._lock:
            self._states.pop(source, None)

    def _evict_if_needed(self) -> None:
        overflow = len(self._states) - self.max_sources
        if overflow <= 0:
            return
        oldest = sorted(self._states.items(), key=lambda item: item[1].last_seen)
        for source, _state in oldest[:overflow]:
            self._states.pop(source, None)


def _normalized_ip(value: Any) -> str:
    try:
        return str(ip_address(str(value or "").strip()))
    except ValueError:
        return ""


def request_source_ip(client_address, headers) -> str:
    """Resolve the client IP, trusting forwarded data only from local Caddy."""

    try:
        peer_raw = client_address[0]
    except (IndexError, TypeError):
        peer_raw = ""
    peer = _normalized_ip(peer_raw)

    try:
        peer_is_loopback = bool(peer and ip_address(peer).is_loopback)
    except ValueError:
        peer_is_loopback = False

    if peer_is_loopback:
        try:
            forwarded = str(headers.get("X-Forwarded-For") or "")
        except Exception:
            forwarded = ""
        # Caddy appends the direct remote address. Taking the final valid element
        # avoids trusting a client-supplied value at the start of the chain.
        for candidate in reversed(forwarded.split(",")):
            normalized = _normalized_ip(candidate)
            if normalized:
                return normalized

    return peer or "unknown"
