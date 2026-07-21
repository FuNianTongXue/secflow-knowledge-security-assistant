from __future__ import annotations

import unittest

from app.go_semantic_analyzer import analyze_go_semantics


class GoSemanticAnalyzerTests(unittest.TestCase):
    def test_reports_discarded_context_cancel(self) -> None:
        result = analyze_go_semantics(
            [
                {
                    "file_name": "context.go",
                    "content": """
package sample
import "context"
func run(parent context.Context) {
    child, _ := context.WithCancel(parent)
    _ = child
}
""",
                }
            ]
        )

        self.assertIn(
            "secflow.go.semantic.context-cancel-leak",
            {item["rule_id"] for item in result["findings"]},
        )

    def test_accepts_deferred_or_returned_cancel(self) -> None:
        result = analyze_go_semantics(
            [
                {
                    "file_name": "context.go",
                    "content": """
package sample
import "context"
func local(parent context.Context) {
    child, cancel := context.WithCancel(parent)
    defer cancel()
    _ = child
}
func owned(parent context.Context) (context.Context, context.CancelFunc) {
    child, cancel := context.WithCancel(parent)
    return child, cancel
}
""",
                }
            ]
        )

        self.assertNotIn(
            "secflow.go.semantic.context-cancel-leak",
            {item["rule_id"] for item in result["findings"]},
        )

    def test_reports_proven_integer_and_slice_overflow(self) -> None:
        result = analyze_go_semantics(
            [
                {
                    "file_name": "bounds.go",
                    "content": """
package sample
import "math"
func run() {
    var value uint32 = math.MaxUint32
    narrowed := int32(value)
    data := make([]byte, 0)
    _ = data[:3]
    _ = narrowed
}
""",
                }
            ]
        )
        rules = {item["rule_id"] for item in result["findings"]}

        self.assertIn("secflow.go.semantic.integer-conversion-overflow", rules)
        self.assertIn("secflow.go.semantic.static-slice-out-of-bounds", rules)

    def test_does_not_report_static_safe_bounds(self) -> None:
        result = analyze_go_semantics(
            [
                {
                    "file_name": "bounds.go",
                    "content": """
package sample
func run() {
    data := make([]byte, 2, 4)
    _ = data[1]
    _ = data[:4]
}
""",
                }
            ]
        )

        self.assertFalse(result["findings"])


if __name__ == "__main__":
    unittest.main()
