import XCTest
@testable import SecFlowMac

final class ModelDecodingTests: XCTestCase {
    func testLiveBackendContractWhenConfigured() async throws {
        guard let serverURL = ProcessInfo.processInfo.environment["SECFLOW_INTEGRATION_URL"] else {
            throw XCTSkip("SECFLOW_INTEGRATION_URL is not configured")
        }
        let client = try APIClient(serverURL: serverURL)
        let config = try await client.loadConfig()
        let collectorGraph = try await client.loadCollectorGraph()
        let dashboard = try await client.loadDashboard()
        let sources = try await client.loadIntelligenceSources()
        let intelligence = try await client.queryIntelligence(
            IntelligenceQueryPayload(query: "CVE-2021-44228", limit: 5, responseLanguage: "zh-Hans", sources: nil)
        )
        let result = try await client.collect(id: "cve")

        XCTAssertNotNil(config.runtime)
        XCTAssertEqual(collectorGraph.nodes.first?.id, "validate_config")
        XCTAssertGreaterThanOrEqual(dashboard.vulnerabilityCount, 1)
        XCTAssertFalse(sources.isEmpty)
        XCTAssertGreaterThanOrEqual(intelligence.graph.nodeCount, 1)
        XCTAssertEqual(result.trace.first?.node, "validate_config")
    }

    func testConfigSnapshotDecodesBackendContract() throws {
        let json = #"""
        {
          "status": "success",
          "message": "ok",
          "data": {
            "collectors": {
              "cve": {
                "id": "cve",
                "name": "CVE Vulnerability Database",
                "enabled": true,
                "api_url": "https://example.test/cves",
                "api_key": "test********key",
                "collection_name": "cve",
                "severity_filter": ["CRITICAL", "HIGH"],
                "dedupe_key": "cve_id",
                "max_results": 20,
                "sync_interval_minutes": 60,
                "last_test": null,
                "last_collect": null
              }
            },
            "records": [{
              "id": "CVE-2026-1000",
              "title": "Example issue",
              "severity": "HIGH",
              "source": "internal",
              "summary": "Example summary",
              "references": [],
              "collection": "cve",
              "updated_at": "2026-07-15T00:00:00+00:00"
            }],
            "stats": {
              "total": 1,
              "by_collection": {"cve": 1},
              "by_severity": {"HIGH": 1}
            },
            "runtime": {
              "llm": {
                "configured": false,
                "provider": "deepseek",
                "model": "deepseek-chat",
                "endpoint": "https://api.deepseek.com/v1",
                "message": "not configured"
              },
              "memory": {
                "enabled": true,
                "backend": "json",
                "historyCount": 2,
                "summaryChars": 0,
                "lastUpdated": "",
                "postgresAvailable": false,
                "postgresError": ""
              }
            }
          }
        }
        """#.data(using: .utf8)!

        let envelope = try JSONDecoder.secFlow.decode(APIEnvelope<ConfigSnapshot>.self, from: json)
        XCTAssertEqual(envelope.data.stats.total, 1)
        XCTAssertEqual(envelope.data.collectors["cve"]?.apiUrl, "https://example.test/cves")
        XCTAssertEqual(envelope.data.runtime?.memory.historyCount, 2)
    }

    func testSettingsSnapshotDecodesBackendContract() throws {
        let json = #"""
        {
          "status": "success",
          "message": "ok",
          "data": {
            "profile": {
              "display_name": "李明哲",
              "email": "limingzhe@example.com",
              "phone": "138 **** 6688",
              "department": "网络安全部",
              "role": "安全分析师",
              "employee_id": "SEC-20240315",
              "bio": "安全分析师",
              "avatar_file_name": "avatar.png",
              "avatar_content_type": "image/png",
              "avatar_updated_at": "2026-07-20T00:00:00+00:00",
              "updated_at": "2026-07-20T00:00:00+00:00",
              "avatar_available": true
            },
            "preferences": {
              "language": "zh-Hans",
              "dark_mode": false,
              "font_size": "default",
              "launch_at_login": false,
              "auto_check_updates": true,
              "updated_at": "2026-07-20T00:00:00+00:00"
            },
            "about": {
              "name": "安全智脑",
              "subtitle": "Security AI Assistant",
              "version": "1.2.0",
              "release_channel": "内测版",
              "version_label": "v1.2.0 内测版",
              "latest": true,
              "last_checked_at": "2024-01-15 14:32",
              "copyright": "© 2024 安全智脑 Security AI. All Rights Reserved.",
              "features": ["智能问答", "情报采集"]
            },
            "legal": {
              "terms": {
                "id": "terms",
                "title": "服务协议",
                "heading": "安全智脑服务协议",
                "updated_at": "2026年7月20日",
                "effective_at": "2026年7月20日",
                "intro": "服务协议正文。",
                "sections": [
                  {
                    "heading": "一、协议",
                    "paragraphs": ["协议内容。"]
                  }
                ],
                "revision_updated_at": ""
              },
              "privacy": {
                "id": "privacy",
                "title": "隐私政策",
                "heading": "安全智脑隐私政策",
                "updated_at": "2026年7月20日",
                "effective_at": "2026年7月20日",
                "intro": "隐私政策正文。",
                "sections": [
                  {
                    "heading": "一、隐私",
                    "paragraphs": ["隐私内容。"]
                  }
                ],
                "revision_updated_at": ""
              }
            }
          }
        }
        """#.data(using: .utf8)!

        let envelope = try JSONDecoder.secFlow.decode(APIEnvelope<SettingsSnapshot>.self, from: json)
        XCTAssertEqual(envelope.data.profile.employeeId, "SEC-20240315")
        XCTAssertTrue(envelope.data.profile.avatarAvailable)
        XCTAssertEqual(envelope.data.preferences.fontSize, "default")
        XCTAssertEqual(envelope.data.about.version, "1.2.0")
        XCTAssertEqual(envelope.data.about.versionLabel, "v1.2.0 内测版")
        XCTAssertEqual(envelope.data.about.features.count, 2)
        XCTAssertEqual(envelope.data.legal?["terms"]?.updatedAt, "2026年7月20日")
        XCTAssertEqual(envelope.data.legal?["privacy"]?.sections.first?.paragraphs.first, "隐私内容。")
    }

    func testAssistantCardAndCollectorTraceDecode() throws {
        let json = #"""
        {
          "status": "success",
          "message": "ok",
          "data": {
            "mode": "vulnerability_lookup",
            "summary": "处置摘要",
            "fields": {},
            "vulnerability_card": {
              "漏洞编号": "CVE-2026-1000",
              "严重等级": "高危",
              "CVSS评分": 9.8,
              "修复版本": "2.0.1"
            },
            "confidence": 0.9,
            "trace": [{
              "node": "collector.normalize_records",
              "status": "completed",
              "message": "规范化完成",
              "time": "2026-07-15T00:00:00+00:00"
            }],
            "generated_at": "2026-07-15T00:00:00+00:00"
          }
        }
        """#.data(using: .utf8)!

        let envelope = try JSONDecoder.secFlow.decode(APIEnvelope<AskResult>.self, from: json)
        XCTAssertEqual(envelope.data.vulnerabilityCard?["漏洞编号"], "CVE-2026-1000")
        XCTAssertEqual(envelope.data.vulnerabilityCard?["CVSS评分"], "9.8")
        XCTAssertEqual(envelope.data.trace.first?.node, "collector.normalize_records")
    }

    func testAssistantDecodesEmptyKnowledgeGraphObject() throws {
        let json = #"""
        {
          "status": "success",
          "message": "ok",
          "data": {
            "mode": "security_knowledge",
            "summary": "通用安全回答",
            "fields": {},
            "vulnerability_card": {},
            "knowledge_graph": {},
            "confidence": 0.82,
            "trace": [],
            "generated_at": "2026-07-15T00:00:00+00:00"
          }
        }
        """#.data(using: .utf8)!

        let envelope = try JSONDecoder.secFlow.decode(APIEnvelope<AskResult>.self, from: json)
        XCTAssertEqual(envelope.data.knowledgeGraph?.nodes, [])
        XCTAssertEqual(envelope.data.knowledgeGraph?.edges, [])
        XCTAssertEqual(envelope.data.knowledgeGraph?.nodeCount, 0)
        XCTAssertEqual(envelope.data.knowledgeGraph?.edgeCount, 0)
    }

    func testAssistantDecodesPartialChartData() throws {
        let json = #"""
        {
          "status": "success",
          "message": "ok",
          "data": {
            "mode": "dependency_vulnerability_report",
            "summary": "依赖分析完成",
            "fields": {},
            "vulnerability_card": {},
            "chart_data": {
              "schema_version": 1,
              "sankey": {
                "nodes": [],
                "links": []
              }
            },
            "confidence": 0.82,
            "trace": [],
            "generated_at": "2026-07-15T00:00:00+00:00"
          }
        }
        """#.data(using: .utf8)!

        let envelope = try JSONDecoder.secFlow.decode(APIEnvelope<AskResult>.self, from: json)
        XCTAssertNotNil(envelope.data.chartData)
        XCTAssertEqual(envelope.data.chartData?.severityRing, [])
        XCTAssertEqual(envelope.data.chartData?.riskBars, [])
        XCTAssertFalse(envelope.data.chartData?.hasContent ?? true)
    }

    func testInformationSnapshotDecodesPublicFeedContract() throws {
        let json = #"""
        {
          "status": "success",
          "message": "ok",
          "data": {
            "items": [{
              "id": "news-1",
              "source_id": "cisa_kev",
              "source_name": "CISA 已知在野利用目录",
              "source_kind": "kev",
              "title": "CVE-2026-1111 已确认在野利用",
              "summary": "Apply the security update.",
              "url": "https://example.test/CVE-2026-1111",
              "image_url": "",
              "source_image_url": "https://example.test/source.png",
              "published_at": "2026-07-19T00:00:00+00:00",
              "author": "CISA KEV",
              "category": "漏洞披露",
              "tags": ["CVE", "在野利用"],
              "breaking": true
            }],
            "total": 1,
            "available_total": 1,
            "categories": [{"id": "all", "label": "全部", "count": 1}],
            "popular_tags": [{"name": "CVE", "count": 1}],
            "briefs": [],
            "sources": [{
              "id": "cisa_kev",
              "name": "CISA 已知在野利用目录",
              "kind": "kev",
              "website": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
              "region": "国际",
              "enabled": true,
              "status": "ready",
              "item_count": 1,
              "last_updated": "2026-07-19T00:00:00+00:00",
              "message": "已获取 1 条"
            }],
            "updated_at": "2026-07-19T00:00:00+00:00",
            "last_refresh": "2026-07-19T00:00:00+00:00",
            "stale": false,
            "partial": false,
            "message": "已更新"
          }
        }
        """#.data(using: .utf8)!

        let envelope = try JSONDecoder.secFlow.decode(APIEnvelope<InformationSnapshot>.self, from: json)

        XCTAssertEqual(envelope.data.items.first?.sourceId, "cisa_kev")
        XCTAssertEqual(envelope.data.items.first?.category, "漏洞披露")
        XCTAssertTrue(envelope.data.items.first?.breaking ?? false)
        XCTAssertEqual(envelope.data.sources.first?.itemCount, 1)
        XCTAssertEqual(envelope.data.sources.first?.region, "国际")
    }

    func testTrialStatusDecodesAndExpiresAt72Hours() throws {
        let json = #"""
        {
          "status": "success",
          "message": "ok",
          "data": {
            "enabled": true,
            "usable": true,
            "state": "active",
            "durationHours": 72,
            "startedAt": "2026-07-20T02:00:00Z",
            "expiresAt": "2026-07-23T02:00:00Z",
            "lastSeenAt": "2026-07-20T02:00:00Z",
            "secondsRemaining": 259200,
            "message": "三天试用版可用。"
          }
        }
        """#.data(using: .utf8)!

        let envelope = try JSONDecoder.secFlow.decode(APIEnvelope<TrialStatusSnapshot>.self, from: json)
        let beforeExpiry = try XCTUnwrap(ISO8601DateFormatter().date(from: "2026-07-23T01:59:59Z"))
        let atExpiry = try XCTUnwrap(ISO8601DateFormatter().date(from: "2026-07-23T02:00:00Z"))

        XCTAssertEqual(envelope.data.durationHours, 72)
        XCTAssertTrue(envelope.data.isUsable(at: beforeExpiry))
        XCTAssertFalse(envelope.data.isUsable(at: atExpiry))
        XCTAssertEqual(envelope.data.remainingSeconds(at: beforeExpiry), 1)
    }
}
