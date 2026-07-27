import sys
from pathlib import Path
from urllib.parse import parse_qs, urlparse
import unittest

ROOT = Path(__file__).resolve().parents[1]
PANEL = ROOT / "panel"
if str(PANEL) not in sys.path:
    sys.path.insert(0, str(PANEL))

import app


class ClientUrlEncodingTests(unittest.TestCase):
    def test_query_url_round_trips_reserved_and_unicode_values(self):
        values = (
            "user+iphone",
            "Иван Телефон",
            "percent%name",
            "hash#name",
            "slash/name",
        )

        for value in values:
            with self.subTest(value=value):
                url = app.query_url("/access", client=value)
                parsed = urlparse(url)
                self.assertEqual(parsed.path, "/access")
                self.assertEqual(parse_qs(parsed.query)["client"], [value])
                self.assertNotIn("#", parsed.query)

    def test_client_route_builders_encode_plus_as_percent_2b(self):
        for builder, expected_path in (
            (app.access_url, "/access"),
            (app.confirm_revoke_delete_url, "/confirm-revoke-delete"),
        ):
            with self.subTest(builder=builder.__name__):
                url = builder("user+iphone")
                parsed = urlparse(url)
                self.assertEqual(parsed.path, expected_path)
                self.assertIn("client=user%2Biphone", parsed.query)
                self.assertEqual(parse_qs(parsed.query)["client"], ["user+iphone"])

    def test_rendered_access_link_uses_encoded_client_name(self):
        page = app.delete_access_result_page("user+iphone", False, ["failed"])
        self.assertIn("/access?client=user%2Biphone", page)
        self.assertNotIn("/access?client=user+iphone", page)

    def test_app_has_no_direct_unencoded_client_query_templates(self):
        source = (PANEL / "app.py").read_text()
        forbidden = (
            "/access?client={esc(",
            "/confirm-revoke-delete?client={esc(",
            'redirect_raw(self, f"/access?client={client}")',
            '"/access?client=" + _urlparse.quote',
        )
        for fragment in forbidden:
            with self.subTest(fragment=fragment):
                self.assertNotIn(fragment, source)


if __name__ == "__main__":
    unittest.main()
