import SwiftUI
import WebKit

struct DependencyChartsView: View {
    @EnvironmentObject private var model: AppModel
    let chartData: DependencyChartData

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(spacing: 8) {
                Image(systemName: "chart.xyaxis.line")
                    .foregroundStyle(AppPalette.primary)
                Text(model.uiText("依赖关系图表"))
                    .font(.headline)
                    .foregroundStyle(AppPalette.text)
                Spacer()
            }

            if let sankey = chartData.sankey, !sankey.nodes.isEmpty, !sankey.links.isEmpty {
                ChartPanel(title: model.uiText("依赖桑基图"), subtitle: model.uiText("构建文件 / 代码文件 → 依赖 → CVE → 修复版本")) {
                    D3SankeyChartView(data: sankey)
                        .frame(height: 320)
                }
            }

            HStack(alignment: .top, spacing: 12) {
                if !chartData.severityRing.isEmpty {
                    ChartPanel(title: model.uiText("风险等级环形图"), subtitle: model.uiText("按严重等级统计漏洞数量")) {
                        SeverityRingChart(metrics: chartData.severityRing)
                            .frame(height: 210)
                    }
                }
                if !chartData.riskBars.isEmpty {
                    ChartPanel(title: model.uiText("依赖风险柱状图"), subtitle: model.uiText("命中漏洞最多的依赖")) {
                        RiskBarChart(metrics: chartData.riskBars)
                            .frame(height: 210)
                    }
                }
            }

            if let dag = chartData.dag, !dag.nodes.isEmpty, !dag.edges.isEmpty {
                ChartPanel(title: model.uiText("依赖影响有向无环图"), subtitle: model.uiText("按层级展示依赖、漏洞与修复路径")) {
                    DependencyDAGChart(data: dag)
                        .frame(minHeight: 280)
                }
            }
        }
        .padding(.top, 6)
    }
}

private struct ChartPanel<Content: View>: View {
    let title: String
    let subtitle: String
    @ViewBuilder let content: Content

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            VStack(alignment: .leading, spacing: 3) {
                Text(title)
                    .font(.callout.weight(.semibold))
                    .foregroundStyle(AppPalette.text)
                Text(subtitle)
                    .font(.caption)
                    .foregroundStyle(AppPalette.textMuted)
            }
            content
        }
        .padding(14)
        .frame(maxWidth: .infinity, alignment: .leading)
        .liquidGlassSurface(cornerRadius: 14, tint: AppPalette.primary)
        .overlay {
            RoundedRectangle(cornerRadius: 14, style: .continuous)
                .stroke(AppPalette.border.opacity(0.72))
        }
    }
}

private struct D3SankeyChartView: NSViewRepresentable {
    let data: SankeyChartData

    func makeNSView(context: Context) -> WKWebView {
        let configuration = WKWebViewConfiguration()
        let webView = WKWebView(frame: .zero, configuration: configuration)
        webView.setValue(false, forKey: "drawsBackground")
        webView.loadHTMLString(html, baseURL: resourceBaseURL)
        return webView
    }

    func updateNSView(_ webView: WKWebView, context: Context) {
        webView.loadHTMLString(html, baseURL: resourceBaseURL)
    }

    private var resourceBaseURL: URL? {
        if let appResourceURL = Bundle.main.resourceURL {
            let bundledURL = appResourceURL
                .appendingPathComponent("SecFlowMac_SecFlowMac.bundle", isDirectory: true)
                .appendingPathComponent("Resources", isDirectory: true)
            if FileManager.default.fileExists(atPath: bundledURL.appendingPathComponent("Web/d3.min.js").path) {
                return bundledURL
            }
        }
        return Bundle.module.resourceURL
    }

    private var html: String {
        let payload = (try? JSONEncoder().encode(data).base64EncodedString()) ?? "eyJub2RlcyI6W10sImxpbmtzIjpbXX0="
        return """
        <!doctype html>
        <html>
        <head>
          <meta charset="utf-8" />
          <meta name="viewport" content="width=device-width,initial-scale=1" />
          <style>
            html, body { margin:0; width:100%; height:100%; overflow:hidden; background:transparent; font-family:-apple-system,BlinkMacSystemFont,"SF Pro Text",sans-serif; }
            #chart { width:100vw; height:100vh; }
            .fallback { height:100vh; display:flex; align-items:center; justify-content:center; color:#5F6874; font-size:13px; }
            .node text { fill:#0F193A; font-size:12px; font-weight:600; paint-order:stroke; stroke:rgba(255,255,255,.72); stroke-width:3px; stroke-linejoin:round; }
            .link { fill:none; mix-blend-mode:multiply; }
            .link:hover { opacity:.92 !important; }
          </style>
          <script src="Web/d3.min.js"></script>
          <script src="Web/d3-sankey.min.js"></script>
        </head>
        <body>
          <div id="chart"></div>
          <script>
            const payload = "\(payload)";
            const raw = JSON.parse(new TextDecoder("utf-8").decode(Uint8Array.from(atob(payload), c => c.charCodeAt(0))));
            const colors = {
              file: "#0F193A", pom: "#0F193A", gradle: "#0F193A", gradle_version_catalog: "#0F193A", gradle_properties: "#0F193A", code: "#334155",
              dependency: "#2CAFD2", vulnerability: "#EF3F3C", fix: "#1EC45B",
              CRITICAL: "#EF3F3C", HIGH: "#F69A00", MEDIUM: "#EDBD00", LOW: "#1EC45B", UNKNOWN: "#94A3B8", CODE: "#2CAFD2"
            };
            function draw() {
              const host = document.getElementById("chart");
              host.innerHTML = "";
              if (!window.d3 || !d3.sankey) {
                host.innerHTML = '<div class="fallback">Sankey runtime is unavailable.</div>';
                return;
              }
              const width = Math.max(640, host.clientWidth || 640);
              const height = Math.max(280, host.clientHeight || 280);
              const svg = d3.select(host).append("svg")
                .attr("viewBox", [0, 0, width, height])
                .attr("width", "100%")
                .attr("height", "100%");
              const graph = {
                nodes: raw.nodes.map(d => ({...d})),
                links: raw.links
                  .filter(d => d.from && d.to && d.from !== d.to)
                  .map(d => ({...d, source: d.from, target: d.to, value: Math.max(1, +d.value || 1)}))
              };
              const sankey = d3.sankey()
                .nodeId(d => d.id)
                .nodeWidth(15)
                .nodePadding(14)
                .nodeAlign(d3.sankeyJustify)
                .extent([[12, 10], [width - 12, height - 18]]);
              const layout = sankey(graph);
              svg.append("g")
                .selectAll("path")
                .data(layout.links)
                .join("path")
                .attr("class", "link")
                .attr("d", d3.sankeyLinkHorizontal())
                .attr("stroke", d => colors[d.severity] || "#2CAFD2")
                .attr("stroke-opacity", .28)
                .attr("stroke-width", d => Math.max(2, d.width))
                .append("title")
                .text(d => `${d.source.label} → ${d.target.label}\\n${d.value}`);
              const node = svg.append("g")
                .selectAll("g")
                .data(layout.nodes)
                .join("g")
                .attr("class", "node");
              node.append("rect")
                .attr("x", d => d.x0)
                .attr("y", d => d.y0)
                .attr("height", d => Math.max(4, d.y1 - d.y0))
                .attr("width", d => d.x1 - d.x0)
                .attr("rx", 4)
                .attr("fill", d => colors[d.severity] || colors[d.type] || "#2CAFD2")
                .attr("fill-opacity", .92);
              node.append("text")
                .attr("x", d => d.x0 < width / 2 ? d.x1 + 7 : d.x0 - 7)
                .attr("y", d => (d.y0 + d.y1) / 2)
                .attr("dy", "0.35em")
                .attr("text-anchor", d => d.x0 < width / 2 ? "start" : "end")
                .text(d => d.label.length > 24 ? d.label.slice(0, 23) + "…" : d.label);
            }
            window.addEventListener("resize", draw);
            setTimeout(draw, 60);
          </script>
        </body>
        </html>
        """
    }
}

private struct SeverityRingChart: View {
    @EnvironmentObject private var model: AppModel
    let metrics: [ChartMetric]

    private var total: Int { max(1, metrics.reduce(0) { $0 + $1.value }) }

    var body: some View {
        HStack(spacing: 16) {
            ZStack {
                ForEach(Array(metrics.enumerated()), id: \.element.id) { index, metric in
                    Circle()
                        .trim(from: start(for: index), to: end(for: index))
                        .stroke(color(for: metric.key ?? metric.id), style: StrokeStyle(lineWidth: 18, lineCap: .round))
                        .rotationEffect(.degrees(-90))
                }
                VStack(spacing: 1) {
                    Text("\(total)")
                        .font(.title3.bold())
                        .foregroundStyle(AppPalette.text)
                    Text(model.uiText("命中"))
                        .font(.caption2)
                        .foregroundStyle(AppPalette.textMuted)
                }
            }
            .frame(width: 128, height: 128)

            VStack(alignment: .leading, spacing: 7) {
                ForEach(metrics) { metric in
                    HStack(spacing: 7) {
                        Circle().fill(color(for: metric.key ?? metric.id)).frame(width: 8, height: 8)
                        Text(severityLabel(metric.key ?? metric.id, language: model.appLanguage))
                            .font(.caption.weight(.medium))
                            .foregroundStyle(AppPalette.text)
                        Spacer()
                        Text("\(metric.value)")
                            .font(.caption.monospacedDigit())
                            .foregroundStyle(AppPalette.textMuted)
                    }
                }
            }
        }
    }

    private func start(for index: Int) -> CGFloat {
        CGFloat(metrics.prefix(index).reduce(0) { $0 + $1.value }) / CGFloat(total)
    }

    private func end(for index: Int) -> CGFloat {
        CGFloat(metrics.prefix(index + 1).reduce(0) { $0 + $1.value }) / CGFloat(total)
    }
}

private struct RiskBarChart: View {
    let metrics: [ChartMetric]
    private var maxValue: Int { max(1, metrics.map(\.value).max() ?? 1) }

    var body: some View {
        VStack(alignment: .leading, spacing: 9) {
            ForEach(metrics.prefix(8)) { metric in
                HStack(spacing: 10) {
                    Text(metric.label ?? metric.id)
                        .font(.caption)
                        .foregroundStyle(AppPalette.text)
                        .lineLimit(1)
                        .frame(width: 112, alignment: .leading)
                    GeometryReader { proxy in
                        ZStack(alignment: .leading) {
                            Capsule().fill(AppPalette.cardMuted)
                            Capsule()
                                .fill(LinearGradient(colors: [AppPalette.brandNavy, AppPalette.primary], startPoint: .leading, endPoint: .trailing))
                                .frame(width: max(6, proxy.size.width * CGFloat(metric.value) / CGFloat(maxValue)))
                        }
                    }
                    .frame(height: 10)
                    Text("\(metric.value)")
                        .font(.caption.monospacedDigit())
                        .foregroundStyle(AppPalette.textMuted)
                        .frame(width: 28, alignment: .trailing)
                }
            }
        }
    }
}

private struct DependencyDAGChart: View {
    let data: DAGChartData

    private var columns: [[ChartNode]] {
        let grouped = Dictionary(grouping: data.nodes) { $0.column ?? 0 }
        return (0...(grouped.keys.max() ?? 0)).map { grouped[$0] ?? [] }
    }

    private var visibleColumns: [[ChartNode]] {
        columns.map { Array($0.prefix(8)) }
    }

    private var minimumHeight: CGFloat {
        let maxColumnCount = visibleColumns.map(\.count).max() ?? 1
        return max(280, CGFloat(maxColumnCount) * 44 + 48)
    }

    var body: some View {
        GeometryReader { proxy in
            let layout = makeLayout(size: proxy.size)
            ZStack {
                Canvas { context, _ in
                    drawEdges(context: &context, layout: layout)
                }

                ForEach(layout.items) { item in
                    DAGNodeCard(node: item.node)
                        .frame(width: item.rect.width, height: item.rect.height)
                        .position(x: item.rect.midX, y: item.rect.midY)
                }
            }
            .background(AppPalette.cardMuted.opacity(0.28))
            .clipShape(RoundedRectangle(cornerRadius: 12, style: .continuous))
            .overlay {
                RoundedRectangle(cornerRadius: 12, style: .continuous)
                    .stroke(AppPalette.primary.opacity(0.10), style: StrokeStyle(lineWidth: 1, dash: [5, 5]))
            }
        }
        .frame(minHeight: minimumHeight)
    }

    private func makeLayout(size: CGSize) -> DAGLayout {
        let columns = visibleColumns
        let columnCount = max(1, columns.count)
        let horizontalPadding: CGFloat = 20
        let verticalPadding: CGFloat = 18
        let cardHeight: CGFloat = 34
        let cardGap: CGFloat = 10
        let availableWidth = max(1, size.width - horizontalPadding * 2)
        let cardWidth = min(172, max(126, availableWidth / CGFloat(columnCount) - 16))
        let horizontalStep = columnCount > 1 ? availableWidth / CGFloat(columnCount - 1) : 0
        var items: [DAGLayoutItem] = []
        var rectsByID: [String: CGRect] = [:]

        for (columnIndex, nodes) in columns.enumerated() {
            let x = columnCount == 1 ? size.width / 2 : horizontalPadding + CGFloat(columnIndex) * horizontalStep
            let totalHeight = CGFloat(nodes.count) * cardHeight + CGFloat(max(0, nodes.count - 1)) * cardGap
            let firstY = max(verticalPadding + cardHeight / 2, (size.height - totalHeight) / 2 + cardHeight / 2)

            for (nodeIndex, node) in nodes.enumerated() {
                let y = firstY + CGFloat(nodeIndex) * (cardHeight + cardGap)
                let rect = CGRect(x: x - cardWidth / 2, y: y - cardHeight / 2, width: cardWidth, height: cardHeight)
                let item = DAGLayoutItem(node: node, rect: rect)
                items.append(item)
                rectsByID[node.id] = rect
            }
        }

        return DAGLayout(items: items, rectsByID: rectsByID)
    }

    private func drawEdges(context: inout GraphicsContext, layout: DAGLayout) {
        for edge in data.edges.prefix(260) {
            guard let from = layout.rectsByID[edge.from], let to = layout.rectsByID[edge.to] else { continue }
            let start = CGPoint(x: from.maxX, y: from.midY)
            let end = CGPoint(x: to.minX, y: to.midY)
            let controlOffset = max(36, (end.x - start.x) * 0.42)
            let control1 = CGPoint(x: start.x + controlOffset, y: start.y)
            let control2 = CGPoint(x: end.x - controlOffset, y: end.y)
            var path = Path()
            path.move(to: start)
            path.addCurve(to: end, control1: control1, control2: control2)

            let tone = color(for: edge.severity ?? edge.type ?? "UNKNOWN")
            context.stroke(path, with: .color(tone.opacity(0.44)), lineWidth: 1.35)
            drawArrowHead(context: &context, end: end, control: control2, tone: tone)
        }
    }

    private func drawArrowHead(context: inout GraphicsContext, end: CGPoint, control: CGPoint, tone: Color) {
        let angle = atan2(end.y - control.y, end.x - control.x)
        let length: CGFloat = 8
        let spread: CGFloat = .pi / 7
        let left = CGPoint(
            x: end.x - length * CGFloat(cos(Double(angle - spread))),
            y: end.y - length * CGFloat(sin(Double(angle - spread)))
        )
        let right = CGPoint(
            x: end.x - length * CGFloat(cos(Double(angle + spread))),
            y: end.y - length * CGFloat(sin(Double(angle + spread)))
        )
        var arrow = Path()
        arrow.move(to: end)
        arrow.addLine(to: left)
        arrow.addLine(to: right)
        arrow.closeSubpath()
        context.fill(arrow, with: .color(tone.opacity(0.72)))
    }
}

private struct DAGLayout {
    let items: [DAGLayoutItem]
    let rectsByID: [String: CGRect]
}

private struct DAGLayoutItem: Identifiable {
    let node: ChartNode
    let rect: CGRect

    var id: String { node.id }
}

private struct DAGNodeCard: View {
    let node: ChartNode

    var body: some View {
        HStack(spacing: 6) {
            Circle()
                .fill(color(for: node.severity ?? node.type))
                .frame(width: 7, height: 7)
            Text(node.label)
                .font(.caption2.weight(.semibold))
                .foregroundStyle(AppPalette.text)
                .lineLimit(1)
                .truncationMode(.middle)
            Spacer(minLength: 0)
        }
        .padding(.horizontal, 9)
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .leading)
        .background(AppPalette.card.opacity(0.90))
        .clipShape(RoundedRectangle(cornerRadius: 9, style: .continuous))
        .overlay {
            RoundedRectangle(cornerRadius: 9, style: .continuous)
                .stroke(color(for: node.severity ?? node.type).opacity(0.22), lineWidth: 1)
        }
        .shadow(color: AppPalette.brandNavy.opacity(0.08), radius: 10, x: 0, y: 6)
    }
}

private func color(for key: String) -> Color {
    switch key.uppercased() {
    case "CRITICAL", "SEVERE", "严重": AppPalette.danger
    case "HIGH", "高危": AppPalette.warning
    case "MEDIUM", "MODERATE", "中危": AppPalette.medium
    case "LOW", "低危": AppPalette.success
    case "CODE": AppPalette.primary
    case "POM", "FILE": AppPalette.brandNavy
    case "DEPENDENCY": AppPalette.primary
    case "FIX": AppPalette.success
    default: AppPalette.textSubtle
    }
}
