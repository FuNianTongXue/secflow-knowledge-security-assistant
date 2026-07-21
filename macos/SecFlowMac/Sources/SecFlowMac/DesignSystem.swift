import SwiftUI

enum AppPalette {
    static let brandNavy = Color(red: 15.0 / 255.0, green: 25.0 / 255.0, blue: 58.0 / 255.0)
    static let brandNavyDeep = Color(red: 10.0 / 255.0, green: 17.0 / 255.0, blue: 42.0 / 255.0)
    static let brandCyan = Color(red: 44.0 / 255.0, green: 175.0 / 255.0, blue: 210.0 / 255.0)
    static let onBrand = Color(red: 0.957, green: 0.973, blue: 0.996)
    static let onBrandMuted = Color(red: 0.733, green: 0.765, blue: 0.839)
    static let page = Color(red: 0.977, green: 0.981, blue: 0.988)
    static let sidebar = brandNavy
    static let card = Color.white
    static let cardMuted = Color(red: 0.963, green: 0.967, blue: 0.974)
    static let border = Color(red: 0.897, green: 0.913, blue: 0.935)
    static let selected = primary.opacity(0.12)
    static let selectedStrong = Color(red: 0.886, green: 0.960, blue: 0.982)
    static let text = Color(red: 0.071, green: 0.083, blue: 0.106)
    static let textMuted = Color(red: 0.393, green: 0.429, blue: 0.477)
    static let textSubtle = Color(red: 0.590, green: 0.620, blue: 0.666)
    static let primary = brandCyan
    static let primaryStrong = Color(red: 21.0 / 255.0, green: 154.0 / 255.0, blue: 191.0 / 255.0)
    static let danger = Color(red: 0.957, green: 0.247, blue: 0.235)
    static let warning = Color(red: 0.965, green: 0.604, blue: 0.000)
    static let medium = Color(red: 0.929, green: 0.741, blue: 0.000)
    static let success = Color(red: 0.118, green: 0.769, blue: 0.357)
}

private struct LiquidGlassSurfaceModifier: ViewModifier {
    let cornerRadius: CGFloat
    let tint: Color

    @ViewBuilder
    func body(content: Content) -> some View {
        if #available(macOS 26.0, *) {
            content
                .background(tint.opacity(0.08), in: RoundedRectangle(cornerRadius: cornerRadius, style: .continuous))
                .glassEffect(.regular, in: .rect(cornerRadius: cornerRadius))
        } else {
            content
                .background(.ultraThinMaterial, in: RoundedRectangle(cornerRadius: cornerRadius, style: .continuous))
                .background(tint.opacity(0.08), in: RoundedRectangle(cornerRadius: cornerRadius, style: .continuous))
        }
    }
}

extension View {
    func liquidGlassSurface(cornerRadius: CGFloat = 8, tint: Color = AppPalette.card) -> some View {
        modifier(LiquidGlassSurfaceModifier(cornerRadius: cornerRadius, tint: tint))
    }
}

struct SidebarGlassBackground: View {
    var body: some View {
        Rectangle()
            .fill(
                LinearGradient(
                    colors: [
                        AppPalette.brandNavy,
                        AppPalette.brandNavyDeep
                    ],
                    startPoint: .topLeading,
                    endPoint: .bottomTrailing
                )
            )
            .overlay(.ultraThinMaterial.opacity(0.18))
            .overlay(AppPalette.primary.opacity(0.045))
            .overlay(alignment: .trailing) {
                Rectangle()
                    .fill(Color.white.opacity(0.10))
                    .frame(width: 1)
            }
    }
}

enum NavigationSection: CaseIterable, Identifiable {
    case overview
    case assistant
    case knowledgeGraph
    case vulnerabilityLibrary
    case information
    case reports

    var id: String { title(.zhHans) }

    func title(_ language: AppLanguage) -> String {
        switch self {
        case .overview: localized(.navOverview, language: language)
        case .assistant: localized(.navAssistant, language: language)
        case .knowledgeGraph: localized(.navKnowledgeGraph, language: language)
        case .vulnerabilityLibrary: localized(.navQueryResults, language: language)
        case .information: localized(.navInformation, language: language)
        case .reports: localized(.navReports, language: language)
        }
    }

    var icon: String {
        switch self {
        case .overview: "square.grid.2x2"
        case .assistant: "message.circle"
        case .knowledgeGraph: "point.3.connected.trianglepath.dotted"
        case .vulnerabilityLibrary: "clock.arrow.circlepath"
        case .information: "newspaper"
        case .reports: "doc.text"
        }
    }
}

struct Panel<Content: View>: View {
    @ViewBuilder let content: Content

    init(@ViewBuilder content: () -> Content) {
        self.content = content()
    }

    var body: some View {
        content
            .padding(18)
            .foregroundStyle(AppPalette.text)
            .liquidGlassSurface(cornerRadius: 8)
            .overlay {
                RoundedRectangle(cornerRadius: 8, style: .continuous)
                    .stroke(AppPalette.border.opacity(0.82))
            }
            .shadow(color: Color.black.opacity(0.055), radius: 14, y: 5)
    }
}

struct StatusBadge: View {
    let text: String
    let tone: StatusTone

    var body: some View {
        Text(text)
            .font(.caption.weight(.semibold))
            .foregroundStyle(tone.color)
            .padding(.horizontal, 8)
            .padding(.vertical, 4)
            .background(tone.color.opacity(0.12))
            .clipShape(Capsule())
    }
}

enum StatusTone {
    case good
    case warning
    case critical
    case info
    case neutral

    var color: Color {
        switch self {
        case .good: AppPalette.success
        case .warning: AppPalette.warning
        case .critical: AppPalette.danger
        case .info: AppPalette.primary
        case .neutral: AppPalette.textMuted
        }
    }

    static func severity(_ value: String) -> StatusTone {
        switch value.uppercased() {
        case "CRITICAL", "SEVERE", "严重": .critical
        case "HIGH", "高危": .warning
        case "MEDIUM", "MODERATE", "中危": .good
        case "LOW", "低危": .info
        default: .neutral
        }
    }

    static func operation(_ value: String) -> StatusTone {
        switch value.lowercased() {
        case "success", "completed": .good
        case "warning": .warning
        case "failed", "error": .critical
        case "running": .info
        default: .neutral
        }
    }
}

struct PageHeader<Trailing: View>: View {
    let title: String
    let subtitle: String?
    @ViewBuilder let trailing: Trailing

    init(_ title: String, subtitle: String? = nil, @ViewBuilder trailing: () -> Trailing) {
        self.title = title
        self.subtitle = subtitle
        self.trailing = trailing()
    }

    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: 16) {
            VStack(alignment: .leading, spacing: 3) {
                Text(title).font(.title2.weight(.semibold))
                    .foregroundStyle(AppPalette.text)
                if let subtitle {
                    Text(subtitle).font(.callout).foregroundStyle(AppPalette.textMuted)
                }
            }
            Spacer()
            trailing
        }
    }
}

extension PageHeader where Trailing == EmptyView {
    init(_ title: String, subtitle: String? = nil) {
        self.init(title, subtitle: subtitle) { EmptyView() }
    }
}

struct TraceView: View {
    @EnvironmentObject private var model: AppModel
    let trace: [TraceItem]

    var body: some View {
        if trace.isEmpty {
            ContentUnavailableView(model.uiText("暂无执行记录"), systemImage: "point.3.connected.trianglepath.dotted")
        } else {
            ScrollView {
                LazyVStack(alignment: .leading, spacing: 0) {
                    ForEach(Array(trace.enumerated()), id: \.element.id) { index, item in
                        HStack(alignment: .top, spacing: 11) {
                            VStack(spacing: 0) {
                                Circle()
                                    .fill(StatusTone.operation(item.status).color)
                                    .frame(width: 9, height: 9)
                                    .padding(.top, 5)
                                if index < trace.count - 1 {
                                    Rectangle()
                                        .fill(AppPalette.textSubtle.opacity(0.25))
                                        .frame(width: 1)
                                        .frame(minHeight: 42)
                                }
                            }
                            VStack(alignment: .leading, spacing: 4) {
                                HStack {
                                    Text(nodeLabel(item.node, language: model.appLanguage)).font(.callout.weight(.semibold))
                                    Spacer()
                                    StatusBadge(text: statusLabel(item.status, language: model.appLanguage), tone: .operation(item.status))
                                }
                                Text(model.localizedMessage(item.message) ?? item.message).font(.caption).foregroundStyle(AppPalette.textMuted)
                                if !item.time.isEmpty {
                                    Text(item.time).font(.caption2.monospacedDigit()).foregroundStyle(AppPalette.textSubtle)
                                }
                            }
                            .padding(.bottom, 12)
                        }
                    }
                }
                .padding(2)
            }
        }
    }
}

struct ErrorBanner: View {
    @EnvironmentObject private var model: AppModel
    let message: String
    let dismiss: () -> Void

    var body: some View {
        HStack(spacing: 10) {
            Image(systemName: "exclamationmark.triangle.fill").foregroundStyle(.red)
            Text(message).font(.callout).lineLimit(2).foregroundStyle(AppPalette.text)
            Spacer()
            Button(action: dismiss) { Image(systemName: "xmark") }
                .buttonStyle(.plain)
                .help(model.uiText("关闭"))
        }
        .padding(10)
        .background(Color.red.opacity(0.08))
        .clipShape(RoundedRectangle(cornerRadius: 6))
    }
}

struct PrimaryActionButtonStyle: ButtonStyle {
    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(.callout.weight(.semibold))
            .foregroundStyle(.white)
            .padding(.horizontal, 13)
            .frame(height: 36)
            .background(configuration.isPressed ? AppPalette.primaryStrong : AppPalette.primary)
            .clipShape(RoundedRectangle(cornerRadius: 7, style: .continuous))
            .shadow(color: AppPalette.primary.opacity(configuration.isPressed ? 0.08 : 0.16), radius: 8, y: 3)
    }
}

struct SecondaryActionButtonStyle: ButtonStyle {
    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(.callout.weight(.semibold))
            .foregroundStyle(AppPalette.text)
            .padding(.horizontal, 13)
            .frame(height: 36)
            .liquidGlassSurface(
                cornerRadius: 7,
                tint: configuration.isPressed ? AppPalette.cardMuted : AppPalette.card
            )
            .overlay {
                RoundedRectangle(cornerRadius: 7, style: .continuous)
                    .stroke(AppPalette.border.opacity(0.82))
            }
            .shadow(color: Color.black.opacity(configuration.isPressed ? 0.025 : 0.05), radius: 8, y: 3)
    }
}

struct LightFieldStyle: TextFieldStyle {
    func _body(configuration: TextField<Self._Label>) -> some View {
        configuration
            .font(.callout)
            .foregroundStyle(AppPalette.text)
            .padding(.horizontal, 11)
            .frame(height: 38)
            .liquidGlassSurface(cornerRadius: 7)
            .overlay {
                RoundedRectangle(cornerRadius: 7, style: .continuous)
                    .stroke(AppPalette.border.opacity(0.86))
            }
    }
}

func severityLabel(_ value: String) -> String {
    switch value.uppercased() {
    case "CRITICAL", "SEVERE", "严重": "严重"
    case "HIGH", "高危": "高危"
    case "MEDIUM", "MODERATE", "中危": "中危"
    case "LOW", "低危": "低危"
    default: "未知"
    }
}

func severityLabel(_ value: String, language: AppLanguage) -> String {
    switch value.uppercased() {
    case "CRITICAL", "SEVERE", "严重": localizedUI("严重", language: language)
    case "HIGH", "高危": localizedUI("高危", language: language)
    case "MEDIUM", "MODERATE", "中危": localizedUI("中危", language: language)
    case "LOW", "低危": localizedUI("低危", language: language)
    default: localizedUI("未知", language: language)
    }
}

func statusLabel(_ value: String) -> String {
    switch value.lowercased() {
    case "success", "completed": "完成"
    case "warning": "警告"
    case "failed", "error": "失败"
    case "running": "运行中"
    case "graph-node": "节点"
    default: value
    }
}

func statusLabel(_ value: String, language: AppLanguage) -> String {
    localizedUI(statusLabel(value), language: language)
}

func nodeLabel(_ node: String) -> String {
    let labels = [
        "classify_query": "识别问题意图",
        "load_memory_context": "加载长期记忆",
        "retrieve_local_knowledge": "检索漏洞知识",
        "fetch_live_vulnerability": "实时补充记录",
        "query_intelligence": "查询漏洞接口",
        "run_static_path_analysis": "静态代码路径分析",
        "enrich_knowledge_graph": "生成知识图谱",
        "query_local_store": "接口查询准备",
        "query_sources": "查询外部接口",
        "persist_intelligence": "接口结果暂存",
        "call_llm": "调用安全模型",
        "translate_vulnerability_card": "整理漏洞卡片",
        "compose_answer": "生成回答",
        "generate_markdown_report": "生成分析报告",
        "persist_memory": "保存长期记忆",
        "validate_config": "准备查询环境",
        "fetch_records": "拉取情报记录",
        "normalize_records": "规范化与去重",
        "persist_records": "跳过本地写入",
        "compose_result": "汇总查询结果",
        "collector.validate_config": "准备查询环境",
        "collector.query_api": "查询漏洞接口",
        "collector.fetch_records": "拉取情报记录",
        "collector.normalize_records": "规范化与去重",
        "collector.persist_records": "跳过本地写入",
        "collector.compose_result": "汇总查询结果",
    ]
    return labels[node] ?? node
}

func nodeLabel(_ node: String, language: AppLanguage) -> String {
    localizedUI(nodeLabel(node), language: language)
}
