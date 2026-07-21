import SwiftUI

struct RootView: View {
    @EnvironmentObject private var model: AppModel
    @State private var selection: NavigationSection? = .overview
    @State private var isSidebarHovered = false
    @State private var hoveredSidebarItem: NavigationSection?

    private let collapsedSidebarWidth: CGFloat = 60
    private let expandedSidebarWidth: CGFloat = 300

    private var isSidebarExpanded: Bool { isSidebarHovered }
    private var sidebarWidth: CGFloat {
        isSidebarExpanded ? expandedSidebarWidth : collapsedSidebarWidth
    }

    var body: some View {
        VStack(spacing: 0) {
            TrialStatusBanner(status: model.trialStatus)
            appContent
        }
        .overlay {
            TrialStatusBlocker(status: model.trialStatus)
        }
        .task {
            await model.refreshTrialStatus()
            await model.runTrialStatusLoop()
        }
    }

    @ViewBuilder
    private var appContent: some View {
        if !model.isAuthenticated {
            AuthView()
        } else {
            switch model.initialSetupState {
            case .loading:
                InitialSetupLoadingView()
                    .task { await model.refreshAll() }
            case .required:
                LLMOnboardingView()
            case .ready:
                workspace
            case let .failed(message):
                InitialSetupFailureView(message: message)
            }
        }
    }

    private var workspace: some View {
        HStack(spacing: 0) {
            sidebar
                .frame(width: sidebarWidth)
                .background { SidebarGlassBackground() }
                .clipped()
                .contentShape(Rectangle())
                .onHover { isInside in
                    withAnimation(.easeInOut(duration: 0.22)) {
                        isSidebarHovered = isInside
                    }
                }

            Divider()
                .overlay(Color.white.opacity(0.08))

            detailContent
                .frame(maxWidth: .infinity, maxHeight: .infinity)
                .layoutPriority(1)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(AppPalette.page)
        .animation(.easeInOut(duration: 0.22), value: isSidebarExpanded)
        .task {
            if model.config == nil { await model.refreshAll() }
            Task { await model.refreshDashboardBatch() }
            await model.runDashboardAutoRefreshLoop()
        }
    }

    private var detailContent: some View {
        VStack(spacing: 0) {
            if let error = model.errorMessage {
                ErrorBanner(message: error) { model.errorMessage = nil }
                    .padding(.horizontal, 20)
                    .padding(.top, 12)
            }

            Group {
                switch selection ?? .overview {
                case .overview:
                    DashboardView {
                        selection = .vulnerabilityLibrary
                    }
                case .assistant: AssistantView()
                case .knowledgeGraph: KnowledgeGraphView()
                case .vulnerabilityLibrary: RecordsView()
                case .information: InformationView()
                case .reports: ReportsView()
                }
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .top)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .top)
        .background(AppPalette.page)
        .foregroundStyle(AppPalette.text)
    }

    private var sidebar: some View {
        VStack(spacing: 0) {
            brand

            ScrollView(.vertical, showsIndicators: false) {
                VStack(alignment: .leading, spacing: 6) {
                    sidebarButton(.overview)
                    sidebarButton(.assistant)
                    sidebarButton(.knowledgeGraph)
                    sidebarButton(.vulnerabilityLibrary)
                    sidebarButton(.information)
                    sidebarButton(.reports)
                }
                .padding(.horizontal, 10)
                .padding(.top, 12)
            }

            Spacer(minLength: 10)
            sidebarLanguageMenu
            userFooter
        }
    }

    private var sidebarLanguageMenu: some View {
        LanguagePickerMenu(compact: !isSidebarExpanded, variant: .sidebar)
            .environmentObject(model)
            .padding(.horizontal, isSidebarExpanded ? 12 : 12)
            .padding(.bottom, 8)
            .transition(.opacity)
    }

    private func sidebarButton(_ item: NavigationSection) -> some View {
        let title = item.title(model.appLanguage)
        return Button {
            selection = item
        } label: {
            SidebarLabel(
                title: title,
                icon: item.icon,
                isActive: isSelected(item),
                isExpanded: isSidebarExpanded,
                isHovered: hoveredSidebarItem == item
            )
        }
        .buttonStyle(.plain)
        .help(title)
        .accessibilityLabel(title)
        .onHover { isInside in
            hoveredSidebarItem = isInside ? item : nil
        }
    }

    private func isSelected(_ item: NavigationSection) -> Bool {
        (selection ?? .overview) == item
    }

    private var brand: some View {
        HStack(spacing: 11) {
            AppBrandLogo(size: 36, shadow: false)

            if isSidebarExpanded {
                VStack(alignment: .leading, spacing: 1) {
                    Text(model.text(.appName))
                        .font(.headline)
                        .foregroundStyle(AppPalette.onBrand)
                        .lineLimit(1)
                    Text(model.text(.appVersion))
                        .font(.caption2)
                        .foregroundStyle(AppPalette.onBrandMuted)
                }
                .transition(.opacity.combined(with: .move(edge: .leading)))

                Spacer(minLength: 0)
            }
        }
        .padding(.horizontal, 12)
        .frame(maxWidth: .infinity, minHeight: 72, alignment: .leading)
        .accessibilityElement(children: .combine)
        .accessibilityLabel("\(model.text(.appName)) \(model.text(.appVersion))")
    }

    private var userFooter: some View {
        VStack(alignment: .leading, spacing: 7) {
            HStack(spacing: 10) {
                Text("李")
                    .font(.callout.bold())
                    .foregroundStyle(.white)
                    .frame(width: 36, height: 36)
                    .background(AppPalette.primary)
                    .clipShape(Circle())

                if isSidebarExpanded {
                    VStack(alignment: .leading, spacing: 1) {
                        Text("李明哲")
                            .font(.callout.weight(.semibold))
                            .foregroundStyle(AppPalette.onBrand)
                        Text(model.uiText("安全分析师"))
                            .font(.caption)
                            .foregroundStyle(AppPalette.onBrandMuted)
                    }
                    .lineLimit(1)
                    .transition(.opacity.combined(with: .move(edge: .leading)))

                    Spacer(minLength: 0)

                    Button { model.signOut() } label: {
                        Image(systemName: "rectangle.portrait.and.arrow.right")
                            .frame(width: 28, height: 28)
                    }
                    .buttonStyle(.plain)
                    .foregroundStyle(AppPalette.onBrandMuted)
                    .help(model.text(.signOut))
                    .transition(.opacity)
                }
            }

            if isSidebarExpanded {
                HStack(spacing: 6) {
                    Circle()
                        .fill(model.config == nil ? AppPalette.danger : AppPalette.success)
                        .frame(width: 6, height: 6)
                    Text(model.config == nil ? model.text(.localServiceStarting) : model.text(.localDataConnected))
                        .font(.caption2)
                        .foregroundStyle(AppPalette.onBrandMuted)
                        .lineLimit(1)
                }
                .transition(.opacity)
            }
        }
        .padding(12)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color.clear)
    }
}

private struct TrialStatusBanner: View {
    let status: TrialStatusSnapshot?

    var body: some View {
        if let status, status.enabled {
            TimelineView(.periodic(from: .now, by: 1)) { context in
                if status.isUsable(at: context.date) {
                    HStack(spacing: 10) {
                        Image(systemName: "clock.badge.exclamationmark")
                            .font(.system(size: 13, weight: .semibold))
                        Text("三天试用版")
                            .font(.caption.weight(.semibold))
                        Spacer(minLength: 12)
                        Text("剩余 \(countdown(status.remainingSeconds(at: context.date)))")
                            .font(.system(.caption, design: .monospaced).weight(.semibold))
                    }
                    .foregroundStyle(Color(red: 0.46, green: 0.25, blue: 0.03))
                    .padding(.horizontal, 16)
                    .frame(maxWidth: .infinity, minHeight: 34)
                    .background(Color(red: 1.0, green: 0.95, blue: 0.82))
                    .overlay(alignment: .bottom) {
                        Rectangle()
                            .fill(Color(red: 0.85, green: 0.62, blue: 0.18).opacity(0.45))
                            .frame(height: 1)
                    }
                }
            }
        }
    }

    private func countdown(_ totalSeconds: Int) -> String {
        let days = totalSeconds / 86_400
        let hours = (totalSeconds % 86_400) / 3_600
        let minutes = (totalSeconds % 3_600) / 60
        let seconds = totalSeconds % 60
        return String(format: "%d天 %02d:%02d:%02d", days, hours, minutes, seconds)
    }
}

struct TrialStatusBlocker: View {
    let status: TrialStatusSnapshot?

    var body: some View {
        if let status, status.enabled {
            TimelineView(.periodic(from: .now, by: 1)) { context in
                TrialBlockedContent(status: status, date: context.date)
            }
        }
    }
}

private struct TrialBlockedContent: View {
    let status: TrialStatusSnapshot
    let date: Date

    var body: some View {
        if !status.isUsable(at: date) {
            ZStack {
                AppPalette.page.opacity(0.98)
                VStack(spacing: 16) {
                    Image(systemName: status.state == "expired" ? "clock.badge.xmark.fill" : "exclamationmark.shield.fill")
                        .font(.system(size: 42, weight: .semibold))
                        .foregroundStyle(AppPalette.danger)
                    Text(status.state == "expired" ? "三天试用已结束" : "试用授权不可用")
                        .font(.title2.weight(.bold))
                        .foregroundStyle(AppPalette.text)
                    Text(status.message)
                        .font(.callout)
                        .foregroundStyle(AppPalette.textMuted)
                        .multilineTextAlignment(.center)
                        .frame(maxWidth: 520)
                    if let started = status.startedDate, let expires = status.expirationDate {
                        VStack(spacing: 8) {
                            trialDateRow("首次启动", started)
                            trialDateRow("到期时间", expires)
                        }
                        .padding(14)
                        .frame(width: 420)
                        .background(AppPalette.card)
                        .clipShape(RoundedRectangle(cornerRadius: 8, style: .continuous))
                        .overlay {
                            RoundedRectangle(cornerRadius: 8, style: .continuous)
                                .stroke(AppPalette.border)
                        }
                    }
                }
                .padding(32)
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
        } else {
            Color.clear
                .frame(width: 0, height: 0)
                .allowsHitTesting(false)
        }
    }

    private func trialDateRow(_ label: String, _ date: Date) -> some View {
        HStack {
            Text(label)
                .foregroundStyle(AppPalette.textMuted)
            Spacer()
            Text(date.formatted(date: .numeric, time: .standard))
                .foregroundStyle(AppPalette.text)
                .monospacedDigit()
        }
        .font(.caption)
    }
}

private struct InitialSetupLoadingView: View {
    @EnvironmentObject private var model: AppModel

    var body: some View {
        VStack(spacing: 14) {
            ProgressView()
                .controlSize(.large)
            Text(model.text(.setupChecking))
                .font(.headline)
                .foregroundStyle(AppPalette.text)
            Text(model.text(.setupCheckingSubtitle))
                .font(.callout)
                .foregroundStyle(AppPalette.textMuted)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(AppPalette.page)
    }
}

private struct InitialSetupFailureView: View {
    @EnvironmentObject private var model: AppModel
    let message: String

    var body: some View {
        VStack(spacing: 16) {
            Image(systemName: "exclamationmark.triangle.fill")
                .font(.system(size: 30))
                .foregroundStyle(AppPalette.warning)
            Text(model.text(.setupFailed))
                .font(.title3.weight(.semibold))
                .foregroundStyle(AppPalette.text)
            Text(message)
                .font(.callout)
                .foregroundStyle(AppPalette.textMuted)
                .multilineTextAlignment(.center)
                .frame(maxWidth: 520)
            Button {
                model.initialSetupState = .loading
            } label: {
                Label(model.text(.retry), systemImage: "arrow.clockwise")
            }
            .buttonStyle(PrimaryActionButtonStyle())
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(AppPalette.page)
    }
}

private struct SidebarLabel: View {
    let title: String
    let icon: String
    let isActive: Bool
    let isExpanded: Bool
    let isHovered: Bool

    var body: some View {
        HStack(spacing: 10) {
            Image(systemName: icon)
                .font(.system(size: 15, weight: .semibold))
                .frame(width: 20, height: 20)

            if isExpanded {
                Text(title)
                    .font(.callout.weight(.medium))
                    .lineLimit(1)
                    .transition(.opacity.combined(with: .move(edge: .leading)))
                Spacer(minLength: 0)
            }
        }
        .foregroundStyle(isActive ? AppPalette.onBrand : AppPalette.onBrandMuted)
        .padding(.horizontal, 10)
        .frame(maxWidth: .infinity, minHeight: 40, alignment: .leading)
        .background {
            RoundedRectangle(cornerRadius: 6, style: .continuous)
                .fill(
                    isActive
                        ? AppPalette.primary.opacity(0.22)
                        : (isHovered ? Color.white.opacity(0.08) : Color.clear)
                )
        }
        .overlay {
            RoundedRectangle(cornerRadius: 6, style: .continuous)
                .stroke(isActive ? AppPalette.primary.opacity(0.36) : Color.clear)
        }
        .contentShape(RoundedRectangle(cornerRadius: 6, style: .continuous))
        .offset(x: isHovered && isExpanded ? 2 : 0)
        .animation(.easeOut(duration: 0.15), value: isHovered)
    }
}
