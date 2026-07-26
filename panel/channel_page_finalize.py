#!/usr/bin/env python3
"""Final presentation boundary for the VPN channel page."""

from __future__ import annotations

from collections.abc import Callable


def finalize_channel_page(
    html: str,
    replace_history: Callable[[str], str],
    logger: Callable[[str], None] | None = None,
) -> str:
    """Apply the history-section replacement and fail open on any error."""

    try:
        return replace_history(html)
    except Exception as exc:
        message = f"vpn_channel_history_period_cards_v1_error={exc!r}"
        try:
            if logger is None:
                print(message, flush=True)
            else:
                logger(message)
        except Exception:
            pass
        return html
