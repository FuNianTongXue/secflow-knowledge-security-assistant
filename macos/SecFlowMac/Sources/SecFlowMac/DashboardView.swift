import Foundation
import SwiftUI

struct DashboardView: View {
    @EnvironmentObject private var model: AppModel
    let openRecords: () -> Void

    @State private var selectedTimePreset: DashboardTimePreset = .all
    @State private var isTimePresetPopoverPresented = false
    @State private var isApplyingTimePreset = false

    private var isRefreshing: Bool {
        model.busyActions.contains("dashboard-batch") || model.busyActions.contains("dashboard-filter")
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 24) {
                dashboardHeader
                dashboardCharts
                metricsGrid
                dashboardContent
            }
            .padding(28)
            .frame(maxWidth: 1280)
            .frame(maxWidth: .infinity, alignment: .top)
        }
        .background(AppPalette.page)
        .foregroundStyle(AppPalette.text)
        .textSelection(.enabled)
        .onAppear { synchronizeTimeFilter() }
        .onChange(of: model.dashboardRange) { _, _ in synchronizeTimeFilter() }
    }

    private var dashboardHeader: some View {
        HStack(alignment: .center, spacing: 20) {
            VStack(alignment: .leading, spacing: 7) {
                Text(model.text(.navOverview))
                    .font(.system(size: 28, weight: .bold))
                    .foregroundStyle(AppPalette.text)
                Text(dashboardScopeText)
                    .font(.callout)
                    .foregroundStyle(AppPalette.textMuted)
                Label(lastUpdatedText, systemImage: "clock")
                    .font(.caption)
                    .foregroundStyle(AppPalette.textSubtle)
                Label(catalogStatusText, systemImage: catalogIsReady ? "externaldrive.fill.badge.checkmark" : "externaldrive.badge.timemachine")
                    .font(.caption)
                    .foregroundStyle(catalogIsReady ? AppPalette.success : AppPalette.primary)
            }

            Spacer(minLength: 12)

            dashboardTimeToolbar
        }
    }

    private var dashboardTimeToolbar: some View {
        HStack(spacing: 8) {
            Button {
                isTimePresetPopoverPresented.toggle()
            } label: {
                HStack(spacing: 8) {
                    if isRefreshing || isApplyingTimePreset {
                        ProgressView()
                            .controlSize(.small)
                    } else {
                        Image(systemName: "calendar")
                            .font(.system(size: 13, weight: .semibold))
                            .foregroundStyle(AppPalette.textMuted)
                    }

                    Text(selectedTimePreset.title(model.appLanguage))
                        .font(.callout.weight(.medium))
                        .foregroundStyle(AppPalette.text)
                        .lineLimit(1)

                    Image(systemName: "chevron.down")
                        .font(.system(size: 9, weight: .bold))
                        .foregroundStyle(AppPalette.textSubtle)
                }
                .padding(.horizontal, 12)
                .frame(height: 36)
                .liquidGlassSurface(cornerRadius: 8)
                .overlay {
                    RoundedRectangle(cornerRadius: 8, style: .continuous)
                        .stroke(AppPalette.border.opacity(0.86))
                }
            }
            .buttonStyle(.plain)
            .disabled(isRefreshing || isApplyingTimePreset)
            .popover(isPresented: $isTimePresetPopoverPresented, arrowEdge: .top) {
                timePresetPopover
            }
            .help(model.text(.dateRangeHelp))

            Button {
                model.statusMessage = model.uiText("暂无新的安全提醒")
            } label: {
                Image(systemName: "bell")
                    .font(.system(size: 14, weight: .semibold))
                    .foregroundStyle(AppPalette.textMuted)
                    .frame(width: 36, height: 36)
                    .liquidGlassSurface(cornerRadius: 8)
                    .overlay {
                        RoundedRectangle(cornerRadius: 8, style: .continuous)
                            .stroke(AppPalette.border.opacity(0.86))
                    }
            }
            .buttonStyle(.plain)
            .help(model.uiText("安全提醒"))
        }
    }

    private var timePresetPopover: some View {
        VStack(spacing: 4) {
            ForEach(DashboardTimePreset.menuOptions) { preset in
                Button {
                    isTimePresetPopoverPresented = false
                    Task { await applyTimePreset(preset) }
                } label: {
                    HStack(spacing: 10) {
                        Image(systemName: selectedTimePreset == preset ? "checkmark" : preset.systemImage)
                            .font(.system(size: 12, weight: .semibold))
                            .foregroundStyle(selectedTimePreset == preset ? AppPalette.primary : AppPalette.textMuted)
                            .frame(width: 16)
                        Text(preset.title(model.appLanguage))
                            .font(.callout.weight(.medium))
                            .foregroundStyle(AppPalette.text)
                        Spacer(minLength: 8)
                    }
                    .padding(.horizontal, 10)
                    .frame(height: 32)
                    .background(selectedTimePreset == preset ? AppPalette.selectedStrong.opacity(0.78) : Color.clear)
                    .clipShape(RoundedRectangle(cornerRadius: 7, style: .continuous))
                }
                .buttonStyle(.plain)
            }
        }
        .padding(8)
        .frame(width: 168)
        .background(AppPalette.card)
        .overlay {
            RoundedRectangle(cornerRadius: 8, style: .continuous)
                .stroke(AppPalette.border.opacity(0.82))
        }
    }

    private var metricsGrid: some View {
        LazyVGrid(
            columns: [GridItem(.adaptive(minimum: 190, maximum: 260), spacing: 16)],
            alignment: .leading,
            spacing: 16
        ) {
            DashboardMetricCard(
                label: model.uiText("漏洞总数"),
                value: vulnerabilityCount,
                icon: "shield.lefthalf.filled",
                color: AppPalette.primary,
                detail: model.uiText("按漏洞编号聚合去重")
            )
            DashboardMetricCard(
                label: model.uiText("严重漏洞"),
                value: severityCount("CRITICAL"),
                icon: "exclamationmark.octagon.fill",
                color: AppPalette.danger,
                detail: shareText(for: "CRITICAL")
            )
            DashboardMetricCard(
                label: model.uiText("高危漏洞"),
                value: severityCount("HIGH"),
                icon: "exclamationmark.triangle.fill",
                color: AppPalette.warning,
                detail: shareText(for: "HIGH")
            )
            DashboardMetricCard(
                label: model.uiText("中危漏洞"),
                value: severityCount("MEDIUM"),
                icon: "exclamationmark.circle.fill",
                color: AppPalette.medium,
                detail: shareText(for: "MEDIUM")
            )
            DashboardMetricCard(
                label: model.uiText("低危漏洞"),
                value: severityCount("LOW"),
                icon: "info.circle.fill",
                color: AppPalette.success,
                detail: shareText(for: "LOW")
            )
        }
    }

    private var dashboardCharts: some View {
        DashboardRiskChartsPanel(
            total: vulnerabilityCount,
            severity: model.dashboard?.severity ?? [:]
        )
    }

    private var dashboardContent: some View {
        ViewThatFits(in: .horizontal) {
            HStack(alignment: .top, spacing: 16) {
                RecentVulnerabilityCard(records: recentRecords, openRecords: openRecords)
                    .frame(minWidth: 560)
                quickStatsColumn
                    .frame(width: 320)
            }

            VStack(spacing: 16) {
                RecentVulnerabilityCard(records: recentRecords, openRecords: openRecords)
                quickStatsColumn
            }
        }
    }

    private var quickStatsColumn: some View {
        VStack(spacing: 16) {
            PriorityRiskCard(records: recentRecords)
        }
    }

    private var vulnerabilityCount: Int {
        model.dashboard?.vulnerabilityCount ?? 0
    }

    private var recentRecords: [IntelligenceRecord] {
        (model.dashboard?.recentRecords ?? []).filter { isKnownSeverity($0.severity) }
    }

    private var lastUpdatedText: String {
        guard let generatedAt = model.dashboard?.generatedAt, !generatedAt.isEmpty else {
            return model.uiText("等待首次批计算")
        }
        return model.uiText("最近更新：%@", dashboardDateTime(generatedAt, locale: model.appLanguage.locale))
    }

    private var dashboardScopeText: String {
        guard model.dashboard?.scope == "range",
              let start = model.dashboard?.rangeStart,
              let end = model.dashboard?.rangeEnd
        else {
            return model.uiText("累计漏洞风险态势，后台持续增量更新")
        }
        return model.uiText("%@ 至 %@ 发布的漏洞风险态势", start, end)
    }

    private var catalogIsReady: Bool {
        model.dashboard?.catalogStatus == "ready"
    }

    private var catalogStatusText: String {
        if catalogIsReady {
            return model.uiText("本地全量目录已就绪，共 %d 条", model.dashboard?.catalogCount ?? vulnerabilityCount)
        }
        let progress = model.dashboard?.catalogProgress ?? 0
        return progress > 0 ? model.uiText("正在构建本地全量目录 %d%%", progress) : model.uiText("正在准备本地全量目录")
    }

    private func synchronizeTimeFilter() {
        selectedTimePreset = DashboardTimePreset.matching(model.dashboardRange)
    }

    private func applyTimePreset(_ preset: DashboardTimePreset) async {
        isApplyingTimePreset = true
        selectedTimePreset = preset
        if let range = preset.range() {
            await model.applyDashboardRange(startDate: range.start, endDate: range.end)
        } else {
            await model.refreshDashboardBatch()
        }
        selectedTimePreset = DashboardTimePreset.matching(model.dashboardRange)
        isApplyingTimePreset = false
    }

    private func severityCount(_ key: String) -> Int {
        model.dashboard?.severity[key] ?? 0
    }

    private func shareText(for key: String) -> String {
        guard vulnerabilityCount > 0 else { return model.uiText("占全部漏洞 0%") }
        let percentage = Int((Double(severityCount(key)) / Double(vulnerabilityCount) * 100).rounded())
        return model.uiText("占全部漏洞 %d%%", percentage)
    }
}

private enum DashboardTimePreset: String, Identifiable, Hashable {
    case all
    case last7Days
    case last30Days
    case last90Days
    case thisYear
    case custom

    static let menuOptions: [DashboardTimePreset] = [
        .all,
        .last7Days,
        .last30Days,
        .last90Days,
        .thisYear
    ]

    var id: String { rawValue }

    func title(_ language: AppLanguage) -> String {
        switch self {
        case .all: return localizedUI("全部时间", language: language)
        case .last7Days: return localizedUI("最近 7 天", language: language)
        case .last30Days: return localizedUI("最近 30 天", language: language)
        case .last90Days: return localizedUI("最近 90 天", language: language)
        case .thisYear: return localizedUI("今年", language: language)
        case .custom: return localizedUI("自定义范围", language: language)
        }
    }

    var systemImage: String {
        switch self {
        case .all: return "clock.arrow.circlepath"
        case .last7Days, .last30Days, .last90Days, .thisYear, .custom: return "calendar"
        }
    }

    func range(
        relativeTo referenceDate: Date = Date(),
        calendar: Calendar = Calendar(identifier: .gregorian)
    ) -> DashboardDateRange? {
        let today = calendar.startOfDay(for: referenceDate)
        switch self {
        case .all, .custom:
            return nil
        case .last7Days:
            return rangeEndingToday(dayCount: 7, today: today, calendar: calendar)
        case .last30Days:
            return rangeEndingToday(dayCount: 30, today: today, calendar: calendar)
        case .last90Days:
            return rangeEndingToday(dayCount: 90, today: today, calendar: calendar)
        case .thisYear:
            let year = calendar.component(.year, from: today)
            let start = calendar.date(from: DateComponents(year: year, month: 1, day: 1)) ?? today
            return DashboardDateRange(start: start, end: today)
        }
    }

    static func matching(
        _ range: DashboardDateRange?,
        relativeTo referenceDate: Date = Date(),
        calendar: Calendar = Calendar(identifier: .gregorian)
    ) -> DashboardTimePreset {
        guard let range else { return .all }
        let start = calendar.startOfDay(for: range.start)
        let end = calendar.startOfDay(for: range.end)

        for preset in menuOptions where preset != .all {
            guard let presetRange = preset.range(relativeTo: referenceDate, calendar: calendar) else { continue }
            if calendar.isDate(start, inSameDayAs: presetRange.start),
               calendar.isDate(end, inSameDayAs: presetRange.end) {
                return preset
            }
        }

        return .custom
    }

    private func rangeEndingToday(dayCount: Int, today: Date, calendar: Calendar) -> DashboardDateRange {
        let offset = max(dayCount - 1, 0)
        let start = calendar.date(byAdding: .day, value: -offset, to: today) ?? today
        return DashboardDateRange(start: start, end: today)
    }
}

private struct DashboardMetricCard: View {
    let label: String
    let value: Int
    let icon: String
    let color: Color
    let detail: String

    @State private var isHovered = false

    var body: some View {
        VStack(alignment: .leading, spacing: 15) {
            HStack {
                Image(systemName: icon)
                    .font(.system(size: 17, weight: .semibold))
                    .foregroundStyle(color)
                    .frame(width: 38, height: 38)
                    .background(color.opacity(0.11))
                    .clipShape(RoundedRectangle(cornerRadius: 8, style: .continuous))

                Spacer()

                Image(systemName: "chart.line.uptrend.xyaxis")
                    .font(.system(size: 13, weight: .semibold))
                    .foregroundStyle(color.opacity(0.75))
            }

            VStack(alignment: .leading, spacing: 5) {
                Text(label)
                    .font(.callout.weight(.medium))
                    .foregroundStyle(AppPalette.textMuted)
                    .lineLimit(1)

                Text(value.formatted())
                    .font(.system(size: 30, weight: .bold, design: .rounded).monospacedDigit())
                    .foregroundStyle(AppPalette.text)
                    .lineLimit(1)
                    .minimumScaleFactor(0.62)

                Text(detail)
                    .font(.caption)
                    .foregroundStyle(color)
                    .lineLimit(1)
                    .minimumScaleFactor(0.8)
            }
        }
        .padding(18)
        .frame(maxWidth: .infinity, minHeight: 154, alignment: .leading)
        .liquidGlassSurface(cornerRadius: 8, tint: color)
        .overlay {
            RoundedRectangle(cornerRadius: 8, style: .continuous)
                .stroke(isHovered ? color.opacity(0.32) : AppPalette.border.opacity(0.82))
        }
        .shadow(color: color.opacity(isHovered ? 0.13 : 0.055), radius: isHovered ? 16 : 11, y: 5)
        .offset(y: isHovered ? -1 : 0)
        .animation(.easeOut(duration: 0.16), value: isHovered)
        .onHover { isHovered = $0 }
    }
}

private struct RecentVulnerabilityCard: View {
    @EnvironmentObject private var model: AppModel
    let records: [IntelligenceRecord]
    let openRecords: () -> Void

    var body: some View {
        Panel {
            VStack(alignment: .leading, spacing: 18) {
                HStack {
                    VStack(alignment: .leading, spacing: 3) {
                        Text(model.uiText("最新漏洞动态"))
                            .font(.headline)
                        Text(model.uiText("最近一次批计算返回的漏洞记录"))
                            .font(.caption)
                            .foregroundStyle(AppPalette.textMuted)
                    }
                    Spacer()
                    Button(model.uiText("查看查询日志"), action: openRecords)
                        .buttonStyle(.plain)
                        .font(.callout.weight(.semibold))
                        .foregroundStyle(AppPalette.primary)
                }

                if records.isEmpty {
                    ContentUnavailableView(
                        model.uiText("暂无漏洞数据"),
                        systemImage: "shield.slash",
                        description: Text(model.uiText("批计算完成后将在这里显示最新漏洞。"))
                    )
                    .frame(minHeight: 310)
                } else {
                    VStack(spacing: 0) {
                        ForEach(Array(records.prefix(5).enumerated()), id: \.element.id) { index, record in
                            VulnerabilityActivityRow(record: record)
                            if index < min(records.count, 5) - 1 {
                                Divider()
                                    .padding(.leading, 50)
                            }
                        }
                    }
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
        }
    }
}

private struct VulnerabilityActivityRow: View {
    @EnvironmentObject private var model: AppModel
    let record: IntelligenceRecord

    private var color: Color {
        severityColor(record.severity)
    }

    var body: some View {
        HStack(spacing: 12) {
            Image(systemName: severityIcon(record.severity))
                .font(.system(size: 15, weight: .semibold))
                .foregroundStyle(color)
                .frame(width: 38, height: 38)
                .background(color.opacity(0.10))
                .clipShape(RoundedRectangle(cornerRadius: 8, style: .continuous))

            VStack(alignment: .leading, spacing: 4) {
                Text(record.title.isEmpty ? model.uiText("未提供漏洞标题") : record.title)
                    .font(.callout.weight(.medium))
                    .foregroundStyle(AppPalette.text)
                    .lineLimit(1)
                    .truncationMode(.tail)
                HStack(spacing: 8) {
                    Text(record.id)
                        .font(.caption.monospaced().weight(.semibold))
                        .foregroundStyle(AppPalette.primary)
                    Text("·")
                        .foregroundStyle(AppPalette.textSubtle)
                    Text(model.uiText("发布于 %@", dashboardDate(record.publishedAt, language: model.appLanguage)))
                        .font(.caption)
                        .foregroundStyle(AppPalette.textMuted)
                }
                .lineLimit(1)
            }
            .layoutPriority(1)

            Spacer(minLength: 8)

            StatusBadge(text: severityLabel(record.severity, language: model.appLanguage), tone: .severity(record.severity))
                .fixedSize(horizontal: true, vertical: false)
                .layoutPriority(2)
        }
        .padding(.vertical, 12)
        .padding(.horizontal, 2)
        .contentShape(Rectangle())
    }
}

private struct DashboardRiskChartsPanel: View {
    @EnvironmentObject private var model: AppModel
    let total: Int
    let severity: [String: Int]

    private var metrics: [DashboardSeverityMetric] {
        [
            DashboardSeverityMetric(
                key: "CRITICAL",
                label: model.uiText("严重"),
                value: count("CRITICAL"),
                color: AppPalette.danger
            ),
            DashboardSeverityMetric(
                key: "HIGH",
                label: model.uiText("高危"),
                value: count("HIGH"),
                color: AppPalette.warning
            ),
            DashboardSeverityMetric(
                key: "MEDIUM",
                label: model.uiText("中危"),
                value: count("MEDIUM"),
                color: AppPalette.medium
            ),
            DashboardSeverityMetric(
                key: "LOW",
                label: model.uiText("低危"),
                value: count("LOW"),
                color: AppPalette.success
            )
        ]
    }

    var body: some View {
        Panel {
            VStack(alignment: .leading, spacing: 18) {
                HStack {
                    VStack(alignment: .leading, spacing: 4) {
                        Text(model.uiText("漏洞情报风险图表"))
                            .font(.headline)
                        Text(model.uiText("按严重等级展示环形图与柱状图"))
                            .font(.caption)
                            .foregroundStyle(AppPalette.textMuted)
                    }
                    Spacer()
                    HStack(spacing: 8) {
                        Image(systemName: "chart.pie.fill")
                            .foregroundStyle(AppPalette.primary)
                        Text(total.formatted())
                            .font(.callout.monospacedDigit().weight(.semibold))
                            .foregroundStyle(AppPalette.text)
                    }
                    .padding(.horizontal, 10)
                    .frame(height: 30)
                    .background(AppPalette.selectedStrong.opacity(0.72))
                    .clipShape(Capsule())
                }

                ViewThatFits(in: .horizontal) {
                    HStack(alignment: .center, spacing: 24) {
                        DashboardSeverityRing(metrics: metrics, total: total)
                            .frame(width: 270, height: 220)
                        DashboardSeverityBarChart(metrics: metrics)
                            .frame(minWidth: 440, maxWidth: .infinity, minHeight: 220)
                    }

                    VStack(spacing: 18) {
                        DashboardSeverityRing(metrics: metrics, total: total)
                            .frame(height: 210)
                        DashboardSeverityBarChart(metrics: metrics)
                            .frame(height: 220)
                    }
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
        }
    }

    private func count(_ key: String) -> Int {
        severity[key] ?? 0
    }
}

private struct DashboardSeverityMetric: Identifiable {
    let key: String
    let label: String
    let value: Int
    let color: Color

    var id: String { key }
}

private struct DashboardSeverityRing: View {
    @EnvironmentObject private var model: AppModel
    let metrics: [DashboardSeverityMetric]
    let total: Int

    private var visibleMetrics: [DashboardSeverityMetric] {
        metrics.filter { $0.value > 0 }
    }

    private var chartTotal: Int {
        max(1, visibleMetrics.reduce(0) { $0 + $1.value })
    }

    var body: some View {
        HStack(spacing: 18) {
            ZStack {
                Circle()
                    .stroke(AppPalette.cardMuted, lineWidth: 22)

                if visibleMetrics.isEmpty {
                    Circle()
                        .trim(from: 0, to: 1)
                        .stroke(AppPalette.primary.opacity(0.32), style: StrokeStyle(lineWidth: 22, lineCap: .round))
                        .rotationEffect(.degrees(-90))
                } else {
                    ForEach(Array(visibleMetrics.enumerated()), id: \.element.id) { index, metric in
                        Circle()
                            .trim(from: ringStart(for: index), to: ringEnd(for: index))
                            .stroke(metric.color, style: StrokeStyle(lineWidth: 22, lineCap: .round))
                            .rotationEffect(.degrees(-90))
                    }
                }

                VStack(spacing: 2) {
                    Text(total.formatted())
                        .font(.system(size: 26, weight: .bold, design: .rounded).monospacedDigit())
                        .foregroundStyle(AppPalette.text)
                        .minimumScaleFactor(0.58)
                        .lineLimit(1)
                    Text(model.uiText("漏洞总数"))
                        .font(.caption2.weight(.medium))
                        .foregroundStyle(AppPalette.textMuted)
                }
                .frame(width: 110)
            }
            .frame(width: 154, height: 154)

            VStack(alignment: .leading, spacing: 9) {
                ForEach(metrics) { metric in
                    HStack(spacing: 8) {
                        Circle()
                            .fill(metric.color)
                            .frame(width: 8, height: 8)
                        Text(metric.label)
                            .font(.caption.weight(.medium))
                            .foregroundStyle(AppPalette.text)
                        Spacer(minLength: 4)
                        Text(metric.value.formatted())
                            .font(.caption.monospacedDigit().weight(.semibold))
                            .foregroundStyle(AppPalette.textMuted)
                    }
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
        }
    }

    private func ringStart(for index: Int) -> CGFloat {
        CGFloat(visibleMetrics.prefix(index).reduce(0) { $0 + $1.value }) / CGFloat(chartTotal)
    }

    private func ringEnd(for index: Int) -> CGFloat {
        CGFloat(visibleMetrics.prefix(index + 1).reduce(0) { $0 + $1.value }) / CGFloat(chartTotal)
    }
}

private struct DashboardSeverityBarChart: View {
    @EnvironmentObject private var model: AppModel
    let metrics: [DashboardSeverityMetric]

    private var maxValue: Int {
        max(1, metrics.map(\.value).max() ?? 1)
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack {
                Text(model.uiText("风险柱状图"))
                    .font(.callout.weight(.semibold))
                    .foregroundStyle(AppPalette.text)
                Spacer()
                Text(model.uiText("按漏洞数量排序"))
                    .font(.caption)
                    .foregroundStyle(AppPalette.textMuted)
            }

            HStack(alignment: .bottom, spacing: 18) {
                ForEach(metrics) { metric in
                    VStack(spacing: 9) {
                        Text(metric.value.formatted())
                            .font(.caption.monospacedDigit().weight(.semibold))
                            .foregroundStyle(AppPalette.text)

                        GeometryReader { proxy in
                            let height = max(8, proxy.size.height * CGFloat(metric.value) / CGFloat(maxValue))
                            ZStack(alignment: .bottom) {
                                RoundedRectangle(cornerRadius: 8, style: .continuous)
                                    .fill(AppPalette.cardMuted)
                                RoundedRectangle(cornerRadius: 8, style: .continuous)
                                    .fill(
                                        LinearGradient(
                                            colors: [
                                                metric.color.opacity(0.82),
                                                metric.key == "CRITICAL" ? AppPalette.danger : AppPalette.primary
                                            ],
                                            startPoint: .bottom,
                                            endPoint: .top
                                        )
                                    )
                                    .frame(height: height)
                            }
                        }
                        .frame(height: 130)

                        HStack(spacing: 5) {
                            Circle()
                                .fill(metric.color)
                                .frame(width: 7, height: 7)
                            Text(metric.label)
                                .font(.caption.weight(.medium))
                                .foregroundStyle(AppPalette.textMuted)
                                .lineLimit(1)
                        }
                    }
                    .frame(maxWidth: .infinity)
                }
            }

            HStack(spacing: 8) {
                Image(systemName: "arrow.up.right.circle.fill")
                    .foregroundStyle(AppPalette.primary)
                Text(model.uiText("数据来自本地批计算快照，并随时间范围筛选实时更新"))
                    .font(.caption)
                    .foregroundStyle(AppPalette.textMuted)
                    .lineLimit(2)
                Spacer(minLength: 0)
            }
            .padding(10)
            .background(AppPalette.primary.opacity(0.055))
            .clipShape(RoundedRectangle(cornerRadius: 8, style: .continuous))
        }
    }
}

private struct RiskProgressRow: View {
    let label: String
    let value: Int
    let total: Int
    let color: Color

    private var progress: Double {
        guard total > 0 else { return 0 }
        return min(max(Double(value) / Double(total), 0), 1)
    }

    var body: some View {
        VStack(spacing: 7) {
            HStack {
                HStack(spacing: 7) {
                    Circle()
                        .fill(color)
                        .frame(width: 7, height: 7)
                    Text(label)
                        .font(.callout)
                        .foregroundStyle(AppPalette.textMuted)
                }
                Spacer()
                Text("\(value.formatted()) · \(Int((progress * 100).rounded()))%")
                    .font(.caption.monospacedDigit().weight(.semibold))
                    .foregroundStyle(AppPalette.text)
            }
            ProgressView(value: progress)
                .progressViewStyle(.linear)
                .tint(color)
        }
    }
}

private struct PriorityRiskCard: View {
    @EnvironmentObject private var model: AppModel
    let records: [IntelligenceRecord]

    private var priorityRecords: [IntelligenceRecord] {
        let knownRecords = records.filter { isKnownSeverity($0.severity) }
        let highRisk = knownRecords.filter { normalizedSeverity($0.severity) == "CRITICAL" || normalizedSeverity($0.severity) == "HIGH" }
        return Array((highRisk.isEmpty ? knownRecords : highRisk).prefix(4))
    }

    var body: some View {
        Panel {
            VStack(alignment: .leading, spacing: 14) {
                Text(model.uiText("重点风险"))
                    .font(.headline)

                if priorityRecords.isEmpty {
                    Text(model.uiText("暂无需要优先关注的漏洞"))
                        .font(.callout)
                        .foregroundStyle(AppPalette.textMuted)
                        .frame(maxWidth: .infinity, minHeight: 80, alignment: .center)
                } else {
                    ForEach(priorityRecords) { record in
                        HStack(spacing: 10) {
                            RoundedRectangle(cornerRadius: 2)
                                .fill(severityColor(record.severity))
                                .frame(width: 4, height: 26)
                            VStack(alignment: .leading, spacing: 2) {
                                Text(record.id)
                                    .font(.caption.monospaced().weight(.semibold))
                                    .foregroundStyle(AppPalette.text)
                                    .lineLimit(1)
                                Text(record.title.isEmpty ? model.uiText("未提供漏洞标题") : record.title)
                                    .font(.caption2)
                                    .foregroundStyle(AppPalette.textMuted)
                                    .lineLimit(1)
                            }
                            Spacer(minLength: 4)
                            Text(priorityValue(record))
                                .font(.caption.monospacedDigit().weight(.semibold))
                                .foregroundStyle(severityColor(record.severity))
                        }
                    }
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
        }
    }

    private func priorityValue(_ record: IntelligenceRecord) -> String {
        if let score = record.cvssScore {
            return String(format: "%.1f", score)
        }
        return severityLabel(record.severity, language: model.appLanguage)
    }
}

private func severityColor(_ value: String) -> Color {
    switch normalizedSeverity(value) {
    case "CRITICAL", "SEVERE", "严重": AppPalette.danger
    case "HIGH", "高危": AppPalette.warning
    case "MEDIUM", "MODERATE", "中危": AppPalette.medium
    case "LOW", "低危": AppPalette.success
    default: AppPalette.textSubtle
    }
}

private func severityIcon(_ value: String) -> String {
    switch normalizedSeverity(value) {
    case "CRITICAL", "SEVERE", "严重": "exclamationmark.octagon.fill"
    case "HIGH", "高危": "exclamationmark.triangle.fill"
    case "MEDIUM", "MODERATE", "中危": "exclamationmark.circle.fill"
    case "LOW", "低危": "info.circle.fill"
    default: "questionmark.circle.fill"
    }
}

private func isKnownSeverity(_ value: String) -> Bool {
    ["CRITICAL", "SEVERE", "HIGH", "MEDIUM", "MODERATE", "LOW", "严重", "高危", "中危", "低危"]
        .contains(normalizedSeverity(value))
}

private func normalizedSeverity(_ value: String) -> String {
    value.trimmingCharacters(in: .whitespacesAndNewlines).uppercased()
}

private func dashboardDate(_ value: String?, language: AppLanguage) -> String {
    guard let value, !value.isEmpty else { return localizedUI("时间未知", language: language) }
    return dashboardDateTime(value, includeTime: false, locale: language.locale)
}

private func dashboardDateTime(_ value: String, includeTime: Bool = true, locale: Locale) -> String {
    let formatter = ISO8601DateFormatter()
    formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
    let date = formatter.date(from: value) ?? ISO8601DateFormatter().date(from: value)
    guard let date else {
        return String(value.prefix(includeTime ? 16 : 10)).replacingOccurrences(of: "T", with: " ")
    }

    let style = Date.FormatStyle(
        date: .abbreviated,
        time: includeTime ? .shortened : .omitted
    )
    .locale(locale)
    return date.formatted(style)
}
