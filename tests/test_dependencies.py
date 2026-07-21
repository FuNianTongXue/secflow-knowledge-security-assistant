from __future__ import annotations

import unittest
import tempfile
from pathlib import Path
from unittest.mock import patch

from app.dependencies import (
    is_allowed_attachment_name,
    parse_code_dependencies,
    parse_gradle_dependencies,
    parse_pom_dependencies,
    scan_dependency_attachments,
)
from app.graph import KnowledgeSecurityGraph, empty_knowledge_graph
from app.reports import ReportStore


class DependencyAttachmentTests(unittest.TestCase):
    def test_attachment_allowlist_accepts_pom_gradle_and_code_only(self) -> None:
        self.assertTrue(is_allowed_attachment_name("pom.xml"))
        self.assertTrue(is_allowed_attachment_name("build.gradle"))
        self.assertTrue(is_allowed_attachment_name("build.gradle.kts"))
        self.assertTrue(is_allowed_attachment_name("settings.gradle"))
        self.assertTrue(is_allowed_attachment_name("gradle/libs.versions.toml"))
        self.assertTrue(is_allowed_attachment_name("gradle.properties"))
        self.assertTrue(is_allowed_attachment_name("src/main/java/Demo.java"))
        self.assertTrue(is_allowed_attachment_name("frontend/App.tsx"))
        self.assertFalse(is_allowed_attachment_name("report.pdf"))
        self.assertFalse(is_allowed_attachment_name("advisory.json"))

    def test_parse_pom_dependencies_resolves_properties(self) -> None:
        dependencies = parse_pom_dependencies(
            "pom.xml",
            """
            <project>
              <properties>
                <log4j.version>2.14.1</log4j.version>
              </properties>
              <dependencies>
                <dependency>
                  <groupId>org.apache.logging.log4j</groupId>
                  <artifactId>log4j-core</artifactId>
                  <version>${log4j.version}</version>
                </dependency>
              </dependencies>
            </project>
            """,
        )

        self.assertEqual(len(dependencies), 1)
        self.assertEqual(dependencies[0].ecosystem, "Maven")
        self.assertEqual(dependencies[0].name, "org.apache.logging.log4j:log4j-core")
        self.assertEqual(dependencies[0].version, "2.14.1")
        self.assertEqual(dependencies[0].confidence, "high")

    def test_code_imports_are_mapped_to_dependency_packages(self) -> None:
        dependencies = parse_code_dependencies(
            "Demo.java",
            """
            import java.util.List;
            import org.apache.logging.log4j.LogManager;
            import com.fasterxml.jackson.databind.ObjectMapper;
            """,
        )
        names = {dependency.name for dependency in dependencies}

        self.assertIn("org.apache.logging.log4j:log4j-core", names)
        self.assertIn("com.fasterxml.jackson.core:jackson-databind", names)
        self.assertNotIn("java.util", names)

    def test_multi_pom_scan_resolves_root_dependency_management_without_counting_it_as_declared(self) -> None:
        result = scan_dependency_attachments(
            [
                {
                    "file_name": "pom.xml",
                    "content": """
                    <project>
                      <properties><hutool.version>5.8.40</hutool.version></properties>
                      <dependencyManagement><dependencies><dependency>
                        <groupId>cn.hutool</groupId><artifactId>hutool-all</artifactId>
                        <version>${hutool.version}</version>
                      </dependency></dependencies></dependencyManagement>
                    </project>
                    """,
                },
                {
                    "file_name": "module/pom.xml",
                    "content": """
                    <project><dependencies><dependency>
                      <groupId>cn.hutool</groupId><artifactId>hutool-all</artifactId>
                    </dependency></dependencies></project>
                    """,
                },
            ]
        )

        self.assertEqual(result["dependency_count"], 1)
        self.assertEqual(result["dependencies"][0]["name"], "cn.hutool:hutool-all")
        self.assertEqual(result["dependencies"][0]["version"], "5.8.40")
        self.assertEqual(result["dependencies"][0]["source_file"], "module/pom.xml")

    def test_spring_boot_starter_uses_explicit_parent_version(self) -> None:
        dependencies = parse_pom_dependencies(
            "pom.xml",
            """
            <project>
              <parent>
                <groupId>org.springframework.boot</groupId>
                <artifactId>spring-boot-starter-parent</artifactId>
                <version>4.1.0</version>
              </parent>
              <dependencies><dependency>
                <groupId>org.springframework.boot</groupId>
                <artifactId>spring-boot-starter-actuator</artifactId>
              </dependency></dependencies>
            </project>
            """,
        )

        self.assertEqual(dependencies[0].version, "4.1.0")

    def test_module_inherits_spring_boot_parent_version_from_uploaded_root_pom(self) -> None:
        result = scan_dependency_attachments(
            [
                {
                    "file_name": "pom.xml",
                    "content": """
                    <project><parent>
                      <groupId>org.springframework.boot</groupId>
                      <artifactId>spring-boot-starter-parent</artifactId>
                      <version>3.5.14</version>
                    </parent></project>
                    """,
                },
                {
                    "file_name": "module/pom.xml",
                    "content": """
                    <project>
                      <parent><groupId>com.example</groupId><artifactId>root</artifactId><version>1.0</version></parent>
                      <dependencies><dependency>
                        <groupId>org.springframework.boot</groupId><artifactId>spring-boot-starter-web</artifactId>
                      </dependency></dependencies>
                    </project>
                    """,
                },
            ]
        )

        self.assertEqual(result["dependencies"][0]["version"], "3.5.14")

    def test_scan_dependency_attachments_rejects_unsupported_files(self) -> None:
        result = scan_dependency_attachments(
            [
                {
                    "file_name": "pom.xml",
                    "content": """
                    <project>
                      <dependencies>
                        <dependency>
                          <groupId>org.yaml</groupId>
                          <artifactId>snakeyaml</artifactId>
                          <version>1.33</version>
                        </dependency>
                      </dependencies>
                    </project>
                    """,
                },
                {"file_name": "notes.json", "content": "{}"},
            ]
        )

        self.assertEqual(result["dependency_count"], 1)
        self.assertEqual(result["dependencies"][0]["name"], "org.yaml:snakeyaml")
        self.assertEqual(result["rejected_files"], ["notes.json"])

    def test_parse_gradle_dependencies_supports_string_and_map_notation(self) -> None:
        dependencies = parse_gradle_dependencies(
            "build.gradle",
            """
            dependencies {
                implementation 'org.apache.logging.log4j:log4j-core:2.14.1'
                testImplementation("org.junit.jupiter:junit-jupiter:5.10.2")
                implementation group: 'org.yaml', name: 'snakeyaml', version: '1.33'
            }
            """,
        )
        by_name = {dependency.name: dependency for dependency in dependencies}

        self.assertEqual(by_name["org.apache.logging.log4j:log4j-core"].version, "2.14.1")
        self.assertEqual(by_name["org.junit.jupiter:junit-jupiter"].version, "5.10.2")
        self.assertEqual(by_name["org.yaml:snakeyaml"].version, "1.33")
        self.assertEqual(by_name["org.yaml:snakeyaml"].source_type, "gradle")
        self.assertEqual(by_name["org.yaml:snakeyaml"].confidence, "high")

    def test_parse_gradle_dependencies_resolves_variables(self) -> None:
        dependencies = parse_gradle_dependencies(
            "build.gradle",
            """
            def jacksonVersion = '2.13.0'
            dependencies {
                implementation "com.fasterxml.jackson.core:jackson-databind:$jacksonVersion"
            }
            """,
        )

        self.assertEqual(len(dependencies), 1)
        self.assertEqual(dependencies[0].name, "com.fasterxml.jackson.core:jackson-databind")
        self.assertEqual(dependencies[0].version, "2.13.0")

    def test_gradle_version_catalog_accessors_resolve_to_dependencies(self) -> None:
        result = scan_dependency_attachments(
            [
                {
                    "file_name": "gradle/libs.versions.toml",
                    "content": """
                    [versions]
                    log4j = "2.14.1"

                    [libraries]
                    log4j-core = { module = "org.apache.logging.log4j:log4j-core", version.ref = "log4j" }
                    junit-jupiter = { group = "org.junit.jupiter", name = "junit-jupiter", version = "5.10.2" }

                    [bundles]
                    test-libs = ["junit-jupiter"]
                    """,
                },
                {
                    "file_name": "build.gradle.kts",
                    "content": """
                    dependencies {
                        implementation(libs.log4j.core)
                        testImplementation(libs.bundles.test.libs)
                    }
                    """,
                },
            ]
        )
        by_name = {dependency["name"]: dependency for dependency in result["dependencies"]}

        self.assertEqual(by_name["org.apache.logging.log4j:log4j-core"]["version"], "2.14.1")
        self.assertEqual(by_name["org.junit.jupiter:junit-jupiter"]["version"], "5.10.2")
        self.assertEqual(by_name["org.apache.logging.log4j:log4j-core"]["source_type"], "gradle")
        self.assertEqual(by_name["org.apache.logging.log4j:log4j-core"]["source_file"], "build.gradle.kts")

    def test_gradle_manifest_dependency_overrides_code_import_without_version(self) -> None:
        result = scan_dependency_attachments(
            [
                {
                    "file_name": "src/main/java/Demo.java",
                    "content": "import org.apache.logging.log4j.LogManager;",
                },
                {
                    "file_name": "build.gradle",
                    "content": """
                    dependencies {
                        implementation 'org.apache.logging.log4j:log4j-core:2.14.1'
                    }
                    """,
                },
            ]
        )

        self.assertEqual(result["dependency_count"], 1)
        self.assertEqual(result["dependencies"][0]["name"], "org.apache.logging.log4j:log4j-core")
        self.assertEqual(result["dependencies"][0]["version"], "2.14.1")
        self.assertEqual(result["dependencies"][0]["source_type"], "gradle")


class DependencyAssistantGraphTests(unittest.TestCase):
    def test_attachment_question_generates_dependency_vulnerability_report(self) -> None:
        record = {
            "id": "CVE-2021-44228",
            "title": "Log4j remote code execution",
            "severity": "CRITICAL",
            "cvss_score": 10.0,
            "summary": "Apache Log4j vulnerable lookup handling.",
            "affected_versions": ["Maven / org.apache.logging.log4j:log4j-core: >= 2.0.0, < 2.15.0"],
            "fixed_versions": ["Maven / org.apache.logging.log4j:log4j-core: 2.15.0"],
            "code_snippets": ["logger.info(userControlledMessage);"],
            "fixed_code_snippets": ["// upgrade log4j-core to 2.15.0 or later"],
            "reference_links": ["https://example.test/CVE-2021-44228"],
            "components": [
                {
                    "ecosystem": "Maven",
                    "name": "org.apache.logging.log4j:log4j-core",
                    "affected": [">= 2.0.0, < 2.15.0"],
                    "fixed": ["2.15.0"],
                }
            ],
            "matched_dependencies": [
                {
                    "ecosystem": "Maven",
                    "name": "org.apache.logging.log4j:log4j-core",
                    "version": "2.14.1",
                    "source_file": "pom.xml",
                    "source_type": "pom",
                    "declaration": "org.apache.logging.log4j:log4j-core:2.14.1",
                    "confidence": "high",
                }
            ],
            "aliases": ["CVE-2021-44228"],
            "updated_at": "2026-07-16T00:00:00+00:00",
        }
        graph = KnowledgeSecurityGraph()
        pom = """
        <project>
          <dependencies>
            <dependency>
              <groupId>org.apache.logging.log4j</groupId>
              <artifactId>log4j-core</artifactId>
              <version>2.14.1</version>
            </dependency>
          </dependencies>
        </project>
        """

        with (
            tempfile.TemporaryDirectory() as temp_dir,
            patch("app.graph.report_store", ReportStore(Path(temp_dir))),
            patch("app.graph.active_model_from_env", return_value=None),
            patch("app.graph.memory_service.build_context", return_value={"enabled": True, "stats": {}, "injectedMessages": []}),
            patch("app.graph.memory_service.add_exchange"),
            patch(
                "app.graph.intelligence_service.query_dependencies",
                return_value={
                    "records": [record],
                    "graph": empty_knowledge_graph("dependency-scan"),
                    "trace": [],
                },
            ) as query_dependencies,
        ):
            result = graph.invoke(
                "请根据附件依赖生成漏洞报告",
                top_k=5,
                attachments=[{"file_name": "pom.xml", "content": pom}],
            )

        query_dependencies.assert_called_once()
        dependency_query = query_dependencies.call_args.args[0]
        self.assertEqual(dependency_query[0]["name"], "org.apache.logging.log4j:log4j-core")
        self.assertEqual(dependency_query[0]["version"], "2.14.1")
        self.assertEqual(result["mode"], "dependency_vulnerability_report")
        self.assertIn("依赖漏洞与代码漏洞分析报告", result["summary"])
        self.assertIn("CVE-2021-44228", result["summary"])
        self.assertIn("org.apache.logging.log4j:log4j-core", result["summary"])
        self.assertNotIn("logger.info", result["summary"])
        self.assertNotIn("upgrade log4j-core", result["summary"])
        self.assertEqual(result["vulnerability_card"]["漏洞编号"], "CVE-2021-44228")
        self.assertIn("logger.info", result["vulnerability_card"]["代码片段"])
        self.assertNotIn("records", result)


if __name__ == "__main__":
    unittest.main()
