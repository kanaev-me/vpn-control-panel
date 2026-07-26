#!/usr/bin/env python3
"""Final presentation boundary for the networks overview page."""

from __future__ import annotations

from collections.abc import Callable


KNOWN_NETWORKS_MARKER = "vpn-known-networks-summary-v1"
CITY_SECTION_ANCHOR = '<section class="card">\n  <h2>Города и регионы</h2>'


def finalize_networks_page(
    html: str,
    build_known_networks: Callable[[], str],
    logger: Callable[[str], None] | None = None,
) -> str:
    """Inject the known-networks summary once and fail open on any error."""

    try:
        if KNOWN_NETWORKS_MARKER in html:
            return html

        insert = build_known_networks()
        if not insert:
            return html

        if CITY_SECTION_ANCHOR in html:
            return html.replace(
                CITY_SECTION_ANCHOR,
                insert + "\n\n" + CITY_SECTION_ANCHOR,
                1,
            )

        return html.replace("</main>", insert + "\n</main>", 1)
    except Exception as exc:
        message = f"known_networks_page_inject_error={exc!r}"
        try:
            if logger is None:
                print(message, flush=True)
            else:
                logger(message)
        except Exception:
            pass
        return html
