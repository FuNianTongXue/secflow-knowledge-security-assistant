from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from app.dependencies import scan_dependency_attachments
from app.language_support import analyze_source_structure, supported_flow_languages
from app.semgrep_tool import SemgrepTool
from scripts.score_labeled_security_corpus import binomial_upper_bound, zero_event_upper_bound


ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "test-fixtures" / "multilang-security"


class MultiLanguageSyntaxTests(unittest.TestCase):
    def test_zero_event_sample_floor_supports_half_percent_upper_bound(self) -> None:
        self.assertGreater(zero_event_upper_bound(597), 0.005)
        self.assertLess(zero_event_upper_bound(598), 0.005)
        self.assertGreater(binomial_upper_bound(1, 598), 0.005)

    def test_tree_sitter_parses_every_supported_flow_language(self) -> None:
        samples = {
            "sample.py": "def run(value):\n    if value:\n        result = value\n        return result\n",
            "sample.go": 'package sample\nfunc run(value string) string { result := value; if result != "" { return result }; return "" }',
            "sample.c": "int run(int value) { int result = value; if (result) { return result; } return 0; }",
            "sample.cpp": "class Demo { public: int run(int value) { int result = value; return result ? 1 : 0; } };",
            "sample.rs": "fn run(value: bool) -> bool { let result = value; if result { true } else { false } }",
            "sample.sol": "pragma solidity ^0.8.20; contract Demo { function run(bool value) public { bool result = value; if (result) { return; } } }",
        }

        analyses = [analyze_source_structure(name, source) for name, source in samples.items()]

        self.assertEqual(set(supported_flow_languages()), {"java", "python", "go", "c", "cpp", "rust", "solidity"})
        self.assertTrue(all(item["parser"] == "tree-sitter" for item in analyses))
        self.assertTrue(all(not item["parse_error"] for item in analyses))
        self.assertTrue(all(item["ast_node_count"] > 0 for item in analyses))
        self.assertTrue(all(item["cfg_node_count"] > 0 for item in analyses))
        self.assertTrue(all(item["cfg_edge_count"] > 0 for item in analyses))
        self.assertTrue(all(item["dfg_edge_count"] > 0 for item in analyses))
        self.assertTrue(all(item["ast_graph"]["nodes"] and item["ast_graph"]["edges"] for item in analyses))
        self.assertTrue(all(item["cfg_graph"]["nodes"] and item["cfg_graph"]["edges"] for item in analyses))
        self.assertTrue(all(item["dfg_graph"]["nodes"] and item["dfg_graph"]["edges"] for item in analyses))

    def test_cfg_records_distinct_true_and_false_branches(self) -> None:
        analysis = analyze_source_structure(
            "sample.py",
            "def run(value):\n    if value:\n        return 1\n    else:\n        return 2\n",
        )
        branches = [edge for edge in analysis["cfg_graph"]["edges"] if edge["kind"].startswith("branch_")]

        self.assertEqual({edge["kind"] for edge in branches}, {"branch_true", "branch_false"})
        self.assertEqual(len({edge["to"] for edge in branches}), 2)

    def test_external_go_qualification_manifest_is_balanced_and_unique(self) -> None:
        manifest = json.loads(
            (ROOT / "config" / "evaluation" / "go-external-random-598x2-2026-07-22.json").read_text(
                encoding="utf-8"
            )
        )
        cases = [case for case in manifest["cases"] if case["partition"] == "qualification"]
        positives = [case for case in cases if case["vulnerable"]]
        negatives = [case for case in cases if not case["vulnerable"]]

        self.assertEqual(len(positives), 598)
        self.assertEqual(len(negatives), 598)
        self.assertEqual(len({case["id"] for case in cases}), 1196)
        self.assertEqual({case["source"] for case in cases}, {"securego/gosec", "semgrep/semgrep-rules"})

    def test_project_manifests_are_recognized_across_new_languages(self) -> None:
        result = scan_dependency_attachments(
            [
                {"file_name": "requirements.txt", "content": "requests==2.32.4\n"},
                {"file_name": "go.mod", "content": "module example.test/app\nrequire github.com/gin-gonic/gin v1.10.0\n"},
                {"file_name": "vcpkg.json", "content": '{"dependencies":[{"name":"openssl","version>=":"3.3.0"}]}'},
                {"file_name": "Cargo.toml", "content": '[dependencies]\nreqwest = "0.12.5"\n'},
                {"file_name": "package.json", "content": '{"dependencies":{"@openzeppelin/contracts":"5.0.2"}}'},
            ]
        )
        dependencies = {(item["ecosystem"], item["name"]): item["version"] for item in result["dependencies"]}

        self.assertEqual(dependencies[("PyPI", "requests")], "2.32.4")
        self.assertEqual(dependencies[("Go", "github.com/gin-gonic/gin")], "v1.10.0")
        self.assertEqual(dependencies[("vcpkg", "openssl")], "3.3.0")
        self.assertEqual(dependencies[("crates.io", "reqwest")], "0.12.5")
        self.assertEqual(dependencies[("npm", "@openzeppelin/contracts")], "5.0.2")


class MultiLanguageRuleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.semgrep = Path(sys.executable).with_name("semgrep")
        if not cls.semgrep.is_file():
            raise unittest.SkipTest("Semgrep executable is not installed next to the test interpreter")

    def test_labeled_multilang_smoke_corpus_has_no_false_results(self) -> None:
        ground_truth = json.loads((FIXTURES / "ground-truth.json").read_text(encoding="utf-8"))
        with tempfile.TemporaryDirectory() as temp_dir:
            result_path = Path(temp_dir) / "results.json"
            completed = subprocess.run(
                [
                    str(self.semgrep),
                    "scan",
                    "--config",
                    str(ROOT / "config" / "semgrep"),
                    "--json-output",
                    str(result_path),
                    "--dataflow-traces",
                    "--metrics=off",
                    "--disable-version-check",
                    "--no-git-ignore",
                    str(FIXTURES),
                ],
                cwd=ROOT,
                capture_output=True,
                text=True,
                timeout=120,
                check=False,
                env={**os.environ, "SEMGREP_SEND_METRICS": "off", "SEMGREP_ENABLE_VERSION_CHECK": "0"},
            )
            self.assertEqual(completed.returncode, 0, completed.stderr or completed.stdout)
            payload = json.loads(result_path.read_text(encoding="utf-8"))

        detected = {
            (
                str(item.get("path") or "").split("multilang-security/", 1)[-1],
                "secflow." + str(item.get("check_id") or "").split("secflow.", 1)[-1],
            )
            for item in payload.get("results") or []
        }
        outcomes = []
        for item in ground_truth:
            matched = (item["file"], item["rule"]) in detected
            outcomes.append("TP" if item["vulnerable"] and matched else "FN" if item["vulnerable"] else "FP" if matched else "TN")

        self.assertEqual(outcomes.count("TP"), 7)
        self.assertEqual(outcomes.count("TN"), 8)
        self.assertEqual(outcomes.count("FP"), 0)
        self.assertEqual(outcomes.count("FN"), 0)

    def test_go_finding_contains_tree_sitter_and_semgrep_flow_evidence(self) -> None:
        source = (FIXTURES / "vulnerable" / "app.go").read_text(encoding="utf-8")
        tool = SemgrepTool(executable=str(self.semgrep))

        result = tool.analyze(
            [{"file_name": "app.go", "content": source}],
            {"files": [{"file_name": "app.go", "kind": "code"}], "dependencies": []},
            [],
        )

        self.assertEqual(result["mode"], "bundled-cli")
        self.assertEqual(result["syntax_summary"]["languages"], ["go"])
        self.assertGreater(result["syntax_summary"]["ast_node_count"], 0)
        finding = next(item for item in result["findings"] if item["rule_id"] == "secflow.go.command-injection")
        self.assertEqual(finding["ast"]["parser"], "tree-sitter")
        self.assertIn("source", [item["kind"] for item in finding["path"]])
        self.assertIn("sink", [item["kind"] for item in finding["path"]])
        self.assertIn("→", finding["dfg"])


if __name__ == "__main__":
    unittest.main()
