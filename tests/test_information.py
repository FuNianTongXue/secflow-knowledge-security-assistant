from __future__ import annotations

import unittest
from copy import deepcopy
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

import app.information as information_module
from app.information import InformationService, parse_article_image, parse_feed, parse_kev
from app.storage import default_state


class FakeStore:
    def __init__(self) -> None:
        self.state = default_state()

    def read(self):
        return deepcopy(self.state)

    def write(self, state):
        self.state = deepcopy(state)


class InformationServiceTests(unittest.TestCase):
    def test_refresh_deduplicates_and_keeps_partial_results(self) -> None:
        fake_store = FakeStore()

        def fetcher(source):
            if source.id == "talos":
                raise RuntimeError("temporary failure")
            return [
                {
                    "title": "Critical CVE-2026-12345 vulnerability is actively exploited",
                    "url": "https://example.test/advisory?utm_source=feed",
                    "summary": "A security patch is available.",
                    "published_at": "2026-07-19T00:00:00Z",
                }
            ]

        snapshot = InformationService(fake_store, fetcher=fetcher).refresh()

        self.assertEqual(snapshot["available_total"], 1)
        self.assertEqual(snapshot["items"][0]["category"], "漏洞披露")
        self.assertIn("CVE", snapshot["items"][0]["tags"])
        self.assertTrue(snapshot["partial"])
        self.assertNotIn("utm_source", snapshot["items"][0]["url"])

    def test_disabled_source_is_not_fetched(self) -> None:
        fake_store = FakeStore()
        called: list[str] = []

        def fetcher(source):
            called.append(source.id)
            return []

        service = InformationService(fake_store, fetcher=fetcher)
        service.set_source_enabled("freebuf", False)
        service.refresh()

        self.assertNotIn("freebuf", called)
        self.assertFalse(fake_store.state["information"]["sources"]["freebuf"]["enabled"])

    def test_rss_and_atom_fields_are_parsed_structurally(self) -> None:
        rss = b"""<?xml version='1.0'?><rss><channel><item>
        <title>Security advisory</title><link>https://example.test/a</link>
        <description><![CDATA[<p>Patch <b>now</b>.</p><img src='https://example.test/a.jpg'>]]></description>
        <pubDate>Sun, 19 Jul 2026 10:00:00 GMT</pubDate></item></channel></rss>"""

        items = parse_feed(rss)

        self.assertEqual(items[0]["title"], "Security advisory")
        self.assertEqual(items[0]["summary"], "Patch now.")
        self.assertEqual(items[0]["image_url"], "https://example.test/a.jpg")

    def test_article_image_prefers_open_graph_metadata(self) -> None:
        html = """<html><head>
        <meta content='/covers/advisory.jpg' property='og:image'>
        </head><body><article><img src='/content/detail.png' width='800'></article></body></html>"""

        image_url = parse_article_image(html, "https://example.test/posts/1")

        self.assertEqual(image_url, "https://example.test/covers/advisory.jpg")

    def test_article_image_uses_main_content_and_ignores_navigation_logo(self) -> None:
        html = """<html><body>
        <nav><img src='/logo.png' width='900' alt='Logo'></nav>
        <div class='markdown-body article-body'><p><img data-src='/images/finding.png' width='640'></p></div>
        </body></html>"""

        image_url = parse_article_image(html, "https://example.test/advisory")

        self.assertEqual(image_url, "https://example.test/images/finding.png")

    def test_article_image_reads_ssr_embedded_html(self) -> None:
        html = """<html><body><script>window.__STATE__ = {
        "content": "<p><img src=\\"https://cdn.example.test/finding.jpg\\" alt=\\"image\\"></p>"
        };</script></body></html>"""

        image_url = parse_article_image(html, "https://example.test/advisory")

        self.assertEqual(image_url, "https://cdn.example.test/finding.jpg")

    def test_information_image_disk_cache_keeps_data_and_mime_separate(self) -> None:
        with TemporaryDirectory() as directory, patch.object(
            information_module,
            "INFORMATION_IMAGE_CACHE_DIR",
            Path(directory),
        ):
            saved = information_module._write_cached_information_image(
                "https://example.test/image.png",
                b"test-image-bytes",
                "image/png",
                "article",
            )
            loaded = information_module._read_cached_information_image(
                "https://example.test/image.png",
                "article",
            )

        self.assertEqual(saved.data, b"test-image-bytes")
        self.assertIsNotNone(loaded)
        self.assertEqual(loaded.data, b"test-image-bytes")
        self.assertEqual(loaded.content_type, "image/png")

    def test_kev_adapter_builds_actionable_items(self) -> None:
        items = parse_kev(
            {
                "vulnerabilities": [
                    {
                        "cveID": "CVE-2026-1111",
                        "vulnerabilityName": "Example flaw",
                        "shortDescription": "Actively exploited.",
                        "requiredAction": "Apply the update.",
                        "dateAdded": "2026-07-18",
                        "vendorProject": "Example",
                        "product": "Widget",
                    }
                ]
            }
        )

        self.assertIn("CVE-2026-1111", items[0]["title"])
        self.assertIn("Apply the update", items[0]["summary"])
        self.assertTrue(items[0]["breaking"])


if __name__ == "__main__":
    unittest.main()
