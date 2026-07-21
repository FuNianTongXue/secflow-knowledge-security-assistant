from __future__ import annotations

import unittest
from pathlib import Path

from app.source_filter import is_analyzable_source_path, is_excluded_source_path


class SourceFilterTests(unittest.TestCase):
    def test_keeps_main_java_sources(self) -> None:
        self.assertTrue(is_analyzable_source_path("module/src/main/java/com/example/App.java"))
        self.assertFalse(is_excluded_source_path(Path("module/src/main/java/com/example/App.java")))
        self.assertTrue(is_analyzable_source_path("module/src/main/java/com/secflow/demo/App.java"))
        self.assertTrue(is_analyzable_source_path("src/main/java/com/example/service/App.java"))

    def test_excludes_common_test_and_benchmark_layouts(self) -> None:
        excluded = [
            "module/src/test/java/com/example/AppTest.java",
            "geode-core/src/distributedTest/java/org/apache/geode/Demo.java",
            "module/src/integrationTest/java/com/example/IT.java",
            "module/src/integration/java/com/example/IT.java",
            "geode-dunit/src/main/java/org/apache/geode/TestCase.java",
            "it/common/src/main/java/org/apache/project/FakeProduction.java",
            "module/src/jmh/java/com/example/Bench.java",
            "examples/java/src/main/java/org/apache/demo/Example.java",
            "example/src/main/java/com/vendor/sample/SampleController.java",
            "sample/src/main/java/com/vendor/payment/SampleController.java",
            "module/src/main/java/org/apache/project/sql/example/ExamplePipeline.java",
            "module/src/main/java/org/apache/project/tutorial/QuickStart.java",
            "module/benchmarks/src/main/java/com/example/Bench.java",
            "module/perf/src/main/java/com/example/Load.java",
        ]

        for path in excluded:
            with self.subTest(path=path):
                self.assertTrue(is_excluded_source_path(path))


if __name__ == "__main__":
    unittest.main()
