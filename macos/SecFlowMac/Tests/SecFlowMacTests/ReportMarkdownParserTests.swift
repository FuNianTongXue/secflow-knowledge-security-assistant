import AppKit
import SwiftUI
import XCTest
@testable import SecFlowMac

final class ReportMarkdownParserTests: XCTestCase {
    func testReportIsSplitIntoCategoryAndFindingCards() throws {
        let markdown = #"""
        # 依赖漏洞与代码漏洞分析报告

        - 依赖漏洞：2 条
        - 代码漏洞：1 条

        ## 3. 依赖漏洞（组件与版本）

        ### 1. CVE-2026-1000

        - 严重等级：HIGH
        - 组件版本范围：1.0.0

        ### 2. CVE-2026-1001

        - 严重等级：MEDIUM

        ## 4. 代码漏洞（文件、行号与修复代码）

        ### 1. 不可信输入到危险调用

        - 风险位置：src/main/java/Demo.java:42

        漏洞代码片段（风险点为第 42 行）：
        ```java
        riskyCall(value);
        ```

        修复后的代码：
        ```java
        safeCall(validate(value));
        ```
        """#

        let document = ReportMarkdownDocument(markdown: markdown)

        XCTAssertEqual(document.title, "依赖漏洞与代码漏洞分析报告")
        XCTAssertTrue(document.overview.contains("依赖漏洞：2 条"))
        XCTAssertEqual(document.sections.map(\.title), [
            "依赖漏洞（组件与版本）",
            "代码漏洞（文件、行号与修复代码）",
        ])
        XCTAssertEqual(document.sections[0].entries.map(\.title), ["CVE-2026-1000", "CVE-2026-1001"])
        XCTAssertEqual(document.sections[1].entries.first?.title, "不可信输入到危险调用")
        XCTAssertTrue(document.sections[1].entries[0].content.contains("src/main/java/Demo.java:42"))
    }

    func testCodeFencesRemainSeparateSelectableBlocks() throws {
        let markdown = #"""
        - 风险位置：Demo.java:42

        ```java
        riskyCall(value);
        ```

        ```java
        safeCall(validate(value));
        ```
        """#

        let blocks = ReportMarkdownBlock.parse(markdown)
        let codeBlocks = blocks.compactMap { block -> (String, String)? in
            guard case let .code(language, content) = block else { return nil }
            return (language, content)
        }

        XCTAssertEqual(codeBlocks.count, 2)
        XCTAssertEqual(codeBlocks[0].0, "java")
        XCTAssertEqual(codeBlocks[0].1, "riskyCall(value);")
        XCTAssertEqual(codeBlocks[1].1, "safeCall(validate(value));")
    }

    func testStyledOverviewParsesMarkerQuoteTableAndRule() throws {
        let markdown = #"""
        <!-- secflow-report-style:v2 -->

        > Generated from scan facts.

        | Item | Result |
        | --- | ---: |
        | Attachments | 25 |
        | Code findings | 1 |

        ---
        """#

        let blocks = ReportMarkdownBlock.parse(markdown)
        XCTAssertEqual(blocks.count, 3)
        guard case let .quote(value) = blocks[0] else {
            return XCTFail("Expected quote block")
        }
        XCTAssertEqual(value, "Generated from scan facts.")
        guard case let .table(headers, rows) = blocks[1] else {
            return XCTFail("Expected table block")
        }
        XCTAssertEqual(headers, ["Item", "Result"])
        XCTAssertEqual(rows, [["Attachments", "25"], ["Code findings", "1"]])
        guard case .rule = blocks[2] else {
            return XCTFail("Expected rule block")
        }
    }

    func testIndentedSourceSinkFenceRemainsCodeBlock() throws {
        let markdown = #"""
        - sink: Demo.java:7
          ```java
          riskyCall(value);
          ```
        """#

        let blocks = ReportMarkdownBlock.parse(markdown)
        let codeBlocks = blocks.compactMap { block -> String? in
            guard case let .code(_, content) = block else { return nil }
            return content
        }

        XCTAssertEqual(codeBlocks, ["  riskyCall(value);"])
    }

    @MainActor
    func testCollapsedReportCategoryCardsRender() throws {
        let markdown = #"""
        # 依赖漏洞与代码漏洞分析报告

        - 生成时间：2026-07-17T04:09:07+00:00
        - 附件数量：2
        - 识别依赖：6 个
        - 依赖漏洞：20 条
        - 代码漏洞：4 条

        ## 1. 执行链路

        - 读取 pom.xml 与代码附件，提取依赖和代码文件。
        - 按依赖组件与版本查询并核验依赖漏洞。

        ## 2. 附件与依赖

        - pom.xml（pom）
        - VulnerableDependencyUsage.java（code）

        ## 3. 依赖漏洞（组件与版本）

        ### 1. CVE-2021-45046

        - 严重等级：CRITICAL
        - 组件版本范围：Maven / org.apache.logging.log4j:log4j-core

        ### 2. CVE-2022-1471

        - 严重等级：HIGH

        ## 4. 代码漏洞（文件、行号与修复代码）

        ### 1. 日志输入处理风险

        - 风险位置：VulnerableDependencyUsage.java:24

        ## 5. 运行摘要

        - 依赖漏洞数量：20
        - 代码漏洞数量：4

        ## 6. 结论摘要

        本次共识别 20 条依赖漏洞和 4 条代码漏洞。
        """#
        let size = NSSize(width: 760, height: 620)
        let hostingView = NSHostingView(
            rootView: MarkdownReportBody(content: markdown)
                .frame(width: size.width, height: size.height)
                .background(AppPalette.card)
                .environmentObject(AppModel())
        )
        hostingView.frame = NSRect(origin: .zero, size: size)
        hostingView.layoutSubtreeIfNeeded()
        let bitmap = try XCTUnwrap(hostingView.bitmapImageRepForCachingDisplay(in: hostingView.bounds))
        hostingView.cacheDisplay(in: hostingView.bounds, to: bitmap)
        let png = try XCTUnwrap(bitmap.representation(using: .png, properties: [:]))
        let image = try XCTUnwrap(NSImage(data: png))
        XCTAssertGreaterThan(image.size.width, 700)
        XCTAssertGreaterThan(image.size.height, 600)
        XCTAssertGreaterThan(nonWhitePixelCount(bitmap), 10_000)

        if let snapshotPath = ProcessInfo.processInfo.environment["SECFLOW_REPORT_SNAPSHOT"] {
            try png.write(to: URL(fileURLWithPath: snapshotPath), options: .atomic)
        }
    }

    private func nonWhitePixelCount(_ bitmap: NSBitmapImageRep) -> Int {
        var count = 0
        for y in stride(from: 0, to: bitmap.pixelsHigh, by: 4) {
            for x in stride(from: 0, to: bitmap.pixelsWide, by: 4) {
                guard let color = bitmap.colorAt(x: x, y: y)?.usingColorSpace(.deviceRGB) else { continue }
                if color.redComponent < 0.97 || color.greenComponent < 0.97 || color.blueComponent < 0.97 {
                    count += 16
                }
            }
        }
        return count
    }
}
