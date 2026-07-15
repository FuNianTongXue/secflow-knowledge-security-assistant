from __future__ import annotations

import unittest

from app.collectors import _github_version_facts, _nvd_affected_versions
from app.graph import build_vulnerability_card, merge_translated_card
from app.privacy import public_answer_payload, severity_cn


class KnowledgeAnswerPrivacyTests(unittest.TestCase):
    def test_public_payload_removes_intelligence_provenance(self) -> None:
        payload = public_answer_payload(
            {
                "mode": "vulnerability_lookup",
                "summary": "NVD 与 GitHub Advisory 检索完成",
                "sources": [{"source": "NVD", "url": "https://example.test"}],
                "records": [{"id": "CVE-2026-0001", "collection": "cve", "references": ["https://example.test"]}],
                "fields": {"数据来源": "NVD", "漏洞链接": "https://example.test"},
                "vulnerability_card": {"严重等级": "HIGH"},
            }
        )
        self.assertNotIn("sources", payload)
        self.assertNotIn("records", payload)
        self.assertEqual(payload["fields"], {})
        self.assertEqual(payload["vulnerability_card"]["严重等级"], "高危")
        self.assertNotIn("NVD", payload["summary"])
        self.assertNotIn("GitHub Advisory", payload["summary"])

    def test_severity_is_chinese(self) -> None:
        self.assertEqual(severity_cn("critical"), "严重")
        self.assertEqual(severity_cn("HIGH"), "高危")
        self.assertEqual(severity_cn("medium"), "中危")
        self.assertEqual(severity_cn("low"), "低危")

    def test_nvd_wildcard_is_not_exposed_as_all_versions(self) -> None:
        cve = {
            "configurations": [
                {
                    "nodes": [
                        {
                            "cpeMatch": [
                                {
                                    "vulnerable": True,
                                    "criteria": "cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*",
                                    "versionEndExcluding": "3.8.0",
                                }
                            ]
                        }
                    ]
                }
            ]
        }
        versions = _nvd_affected_versions(cve)
        self.assertEqual(versions, ["acme widget < 3.8.0"])
        self.assertNotIn("*", versions[0])
        self.assertNotIn("所有版本", versions[0])

    def test_fixed_version_cannot_be_invented_by_translation(self) -> None:
        record = {
            "id": "CVE-2026-0001",
            "title": "Example issue",
            "summary": "Example description",
            "severity": "HIGH",
            "affected_versions": ["acme widget < 3.8.0"],
            "fixed_versions": [],
        }
        fallback = build_vulnerability_card(record)
        translated = merge_translated_card({"修复版本": "99.0.0"}, fallback, record)
        self.assertEqual(translated["修复版本"], "未明确")

    def test_github_fixed_version_is_kept_as_fact(self) -> None:
        affected, fixed = _github_version_facts(
            {
                "vulnerabilities": [
                    {
                        "package": {"ecosystem": "pip", "name": "demo"},
                        "vulnerable_version_range": "< 2.4.1",
                        "first_patched_version": {"identifier": "2.4.1"},
                    }
                ]
            }
        )
        self.assertEqual(affected, ["pip / demo: < 2.4.1"])
        self.assertEqual(fixed, ["pip / demo: 2.4.1"])


if __name__ == "__main__":
    unittest.main()
