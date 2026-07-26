#!/usr/bin/env python3
"""Ordered orchestration for profile-data enrichment stages."""

from __future__ import annotations

from collections.abc import Callable, Iterable
from typing import Any


ProfileData = dict[str, Any]
ProfileStage = Callable[[str, str, ProfileData], ProfileData]


def run_profile_data_pipeline(
    client: str,
    old_html: str,
    data: ProfileData,
    stages: Iterable[ProfileStage],
) -> ProfileData:
    """Run profile enrichment stages in order, forwarding each returned object.

    Individual stages retain their historical fail-open behavior. This
    orchestrator intentionally does not swallow exceptions: the final provider
    normalization wrapper previously propagated unexpected runtime failures.
    """

    current = data
    for stage in stages:
        current = stage(client, old_html, current)
    return current
