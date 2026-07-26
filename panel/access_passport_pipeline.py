#!/usr/bin/env python3
"""Ordered orchestration for access passport presentation stages."""

from __future__ import annotations

from collections.abc import Callable, Iterable
from typing import Any


PageStage = Callable[[str, Any, str], str]


def run_access_passport_pipeline(
    client: str,
    user: Any,
    html: str,
    stages: Iterable[PageStage],
) -> str:
    """Run access passport presentation stages in their declared order.

    Every historical stage retains its own fail-open boundary. The orchestrator
    intentionally forwards unexpected exceptions instead of hiding new defects.
    """

    current = html
    for stage in stages:
        current = stage(client, user, current)
    return current
