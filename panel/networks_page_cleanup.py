#!/usr/bin/env python3
"""Explicit presentation pipeline for the /networks page."""

from __future__ import annotations

import re


_NETWORK_LABELS = {}

def cleanup_networks_v3(page: str) -> str:
    """Remove duplicated shell heading and add the compact v3 stylesheet."""

    page = re.sub(
        r"(<main\b[^>]*>)\s*<h1[^>]*>.*?</h1>\s*<p[^>]*>.*?</p>",
        r"\1",
        page,
        count=1,
        flags=re.S | re.I,
    )

    css = """
<style>
/* vpn-networks-v3 */
body:has(.vpn-networks-v2) main > h1:first-of-type,
body:has(.vpn-networks-v2) main > h1:first-of-type + p{display:none!important}
.vpn-networks-v2{gap:12px!important}
.n2-hero,.n2-section{padding:14px!important}
.n2-hero h1{font-size:30px!important}
.n2-hero p,.n2-section>p{font-size:16px!important}
.n2-stats{gap:8px!important}
.n2-stat{padding:10px!important}
.n2-stat strong{font-size:22px!important}
.n2-card code{font-family:inherit!important;letter-spacing:0!important;word-spacing:0!important}
.n2-card,.n2-match,.n2-city{padding:11px!important}
.n2-grid{gap:9px!important}
.n2-match{grid-template-columns:62px 1fr!important}
@media(max-width:720px){
  .n2-match{grid-template-columns:1fr!important}
  .n2-score{width:100%;box-sizing:border-box}
}
/* /vpn-networks-v3 */
</style>
"""
    page = page.replace("</head>", css + "\n</head>", 1) if "</head>" in page else css + page
    return page + "\n<!-- vpn-networks-v3 -->\n"


def cleanup_networks_v4_lite(page: str) -> str:
    """Apply the historical label replacements and compact serialized HTML."""

    page = re.sub(
        r"(<main\b[^>]*>)\s*<h1[^>]*>Сети и совпадения</h1>\s*<p[^>]*>.*?</p>",
        r"\1",
        page,
        count=1,
        flags=re.S | re.I,
    )

    for technical, label in sorted(_NETWORK_LABELS.items(), key=lambda item: -len(item[0])):
        page = re.sub(
            r"(?<![A-Za-z0-9_.-])" + re.escape(technical) + r"(?![A-Za-z0-9_.-])",
            label,
            page,
        )

    page = re.sub(r"\s+", " ", page)
    page = page.replace("> <", "><")
    return page + "\n<!-- vpn-networks-v4-lite -->\n"


def cleanup_networks_title_fix(page: str) -> str:
    """Remove any remaining shell title before the networks product surface."""

    cut = page.find('<div class="vpn-networks-v2">')
    if cut != -1:
        before = page[:cut]
        after = page[cut:]
        before = re.sub(
            r"<h1[^>]*>\s*Сети и совпадения\s*</h1>\s*<p[^>]*>.*?</p>",
            "",
            before,
            flags=re.S | re.I,
        )
        before = re.sub(
            r"<h1[^>]*>\s*Сети и совпадения\s*</h1>",
            "",
            before,
            flags=re.S | re.I,
        )
        page = before + after

    return page + "\n<!-- vpn-networks-title-fix-v1 -->\n"


def cleanup_networks_page(page: str) -> str:
    """Run the three historical cleanup stages in their original order."""

    page = cleanup_networks_v3(page)
    page = cleanup_networks_v4_lite(page)
    return cleanup_networks_title_fix(page)
