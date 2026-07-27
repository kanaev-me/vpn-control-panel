#!/usr/bin/env python3
"""One-time exact transformer for the client query URL fix."""

from __future__ import annotations

import hashlib
from pathlib import Path

APP = Path(__file__).resolve().parents[1] / "panel" / "app.py"
EXPECTED_BEFORE = "417b82e526f7e16e92550d39234cf2181961c3a7"
EXPECTED_AFTER = "737230760475bb5a679476629025ec518a47f00b"


def git_blob_sha(data: bytes) -> str:
    header = f"blob {len(data)}\0".encode("ascii")
    return hashlib.sha1(header + data).hexdigest()


def replace_required(source: str, old: str, new: str, count: int | None = None) -> str:
    actual = source.count(old)
    expected = actual if count is None else count
    if actual != expected or actual == 0:
        raise RuntimeError(f"replacement count mismatch: expected={expected} actual={actual} fragment={old!r}")
    return source.replace(old, new)


def main() -> None:
    before = APP.read_bytes()
    before_sha = git_blob_sha(before)
    if before_sha == EXPECTED_AFTER:
        print("client_url_fix=already_applied")
        return
    if before_sha != EXPECTED_BEFORE:
        raise RuntimeError(f"unexpected panel/app.py blob: {before_sha}")

    source = before.decode("utf-8")
    source = replace_required(
        source,
        "from urllib.parse import urlparse, parse_qs\n",
        "from urllib.parse import urlparse, parse_qs, quote\n",
        1,
    )
    source = replace_required(
        source,
        "def esc(x):\n    return html.escape(str(x), quote=True)\n\n",
        """def esc(x):
    return html.escape(str(x), quote=True)

def query_url(path, **params):
    query = "&".join(
        f"{quote(str(name), safe='')}={quote(str(value or ''), safe='')}"
        for name, value in params.items()
    )
    return f"{path}?{query}" if query else str(path)

def access_url(client):
    return query_url("/access", client=client)

def confirm_revoke_delete_url(client):
    return query_url("/confirm-revoke-delete", client=client)

""",
        1,
    )

    replacements = (
        (
            'passport_link = f\'<a class="softButton" href="/access?client={esc(client)}">Открыть паспорт доступа</a>\'',
            'passport_link = f\'<a class="softButton" href="{esc(access_url(client))}">Открыть паспорт доступа</a>\'',
        ),
        (
            '<a class="primaryButton" href="/access?client={esc(client)}">Открыть паспорт доступа</a>',
            '<a class="primaryButton" href="{esc(access_url(client))}">Открыть паспорт доступа</a>',
        ),
        (
            '<a class="create-back-link" href="/access?client={esc(client)}">← В паспорт доступа</a>',
            '<a class="create-back-link" href="{esc(access_url(client))}">← В паспорт доступа</a>',
        ),
        (
            '<a class="softButton" href="/access?client={esc(client)}">Отмена</a>',
            '<a class="softButton" href="{esc(access_url(client))}">Отмена</a>',
        ),
        (
            '<a class="dangerButton" href="/confirm-revoke-delete?client={esc(client)}">Отключить и удалить</a>',
            '<a class="dangerButton" href="{esc(confirm_revoke_delete_url(client))}">Отключить и удалить</a>',
        ),
        (
            "f\"<tr><td><span class='pill bad'>сейчас</span></td><td><a href='/access?client={esc(client)}'>{esc(client)}</a></td><td>одновременно активен с разных IP — проверить, не используется ли один конфиг на двух устройствах</td></tr>\"",
            "f\"<tr><td><span class='pill bad'>сейчас</span></td><td><a href='{esc(access_url(client))}'>{esc(client)}</a></td><td>одновременно активен с разных IP — проверить, не используется ли один конфиг на двух устройствах</td></tr>\"",
        ),
        (
            "f\"<tr><td><span class='pill warn'>проверить</span></td><td><a href='/access?client={esc(client)}'>{esc(client)}</a></td><td>{esc(reason)}</td></tr>\"",
            "f\"<tr><td><span class='pill warn'>проверить</span></td><td><a href='{esc(access_url(client))}'>{esc(client)}</a></td><td>{esc(reason)}</td></tr>\"",
        ),
        (
            "f\"<tr><td><span class='pill warn'>старый профиль</span></td><td><a href='/access?client={esc(client)}'>{esc(client)}</a></td><td>{esc(detail)}</td></tr>\"",
            "f\"<tr><td><span class='pill warn'>старый профиль</span></td><td><a href='{esc(access_url(client))}'>{esc(client)}</a></td><td>{esc(detail)}</td></tr>\"",
        ),
        ('"href": href or f"/access?client={esc(client)}",', '"href": href or access_url(client),'),
        (
            '<a class="person-device {\'is-online\' if connected else \'\'}" href="/access?client={esc(d[\'client\'])}">',
            '<a class="person-device {\'is-online\' if connected else \'\'}" href="{esc(access_url(d[\'client\']))}">',
        ),
        (
            'f"<td><a href=\'/access?client={esc(name)}\'>{esc(name)}</a></td>"',
            'f"<td><a href=\'{esc(access_url(name))}\'>{esc(name)}</a></td>"',
        ),
        (
            '<a class="home-check-row warn" href="/access?client={esc(client)}">',
            '<a class="home-check-row warn" href="{esc(access_url(client))}">',
        ),
        ('redirect_raw(self, f"/access?client={client}")', 'redirect_raw(self, access_url(client))'),
        ('href = "/access?client=" + _urlparse.quote(other)', 'href = access_url(other)'),
        ('href = "/access?client=" + _urlparse.quote(c)', 'href = access_url(c)'),
        ('href_a = "/access?client=" + _urlparse.quote(a)', 'href_a = access_url(a)'),
        ('href_b = "/access?client=" + _urlparse.quote(b)', 'href_b = access_url(b)'),
    )
    for old, new in replacements:
        source = replace_required(source, old, new)

    source = replace_required(
        source,
        'def access_matches_panel_html(client):\n    """Shows smart related accesses in access passport."""\n    import sqlite3 as _sqlite3\n    import urllib.parse as _urlparse\n',
        'def access_matches_panel_html(client):\n    """Shows smart related accesses in access passport."""\n    import sqlite3 as _sqlite3\n',
        1,
    )
    source = replace_required(
        source,
        'def networks_page_v1(user=None):\n    import json as _json\n    import sqlite3 as _sqlite3\n    import urllib.parse as _urlparse\n',
        'def networks_page_v1(user=None):\n    import json as _json\n    import sqlite3 as _sqlite3\n',
        1,
    )
    source = replace_required(
        source,
        'def _v4_render_profile(client, user=None, old_html=""):\n    import json as _json\n    import urllib.parse as _urlparse\n',
        'def _v4_render_profile(client, user=None, old_html=""):\n    import json as _json\n',
        1,
    )

    after = source.encode("utf-8")
    after_sha = git_blob_sha(after)
    if after_sha != EXPECTED_AFTER:
        raise RuntimeError(f"unexpected transformed blob: {after_sha}")
    APP.write_bytes(after)
    print(f"client_url_fix=applied blob={after_sha}")


if __name__ == "__main__":
    main()
