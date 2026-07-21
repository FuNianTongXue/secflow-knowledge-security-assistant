import AppKit
import SwiftUI

struct InformationView: View {
    @EnvironmentObject private var model: AppModel
    @Environment(\.openURL) private var openURL

    @State private var searchText = ""
    @State private var selectedCategory = "全部"
    @State private var sortMode: InformationSortMode = .latest
    @State private var visibleCount = 14

    private var isRefreshing: Bool {
        model.busyActions.contains("information-refresh")
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 18) {
                header
                categoryBar
                content
            }
            .padding(24)
            .frame(maxWidth: 1380)
            .frame(maxWidth: .infinity, alignment: .top)
        }
        .defaultScrollAnchor(.top)
        .background(AppPalette.page)
        .foregroundStyle(AppPalette.text)
        .task {
            if model.information == nil {
                await model.refreshInformation()
            }
            while !Task.isCancelled {
                try? await Task.sleep(nanoseconds: 600_000_000_000)
                guard !Task.isCancelled else { return }
                await model.refreshInformation()
            }
        }
        .onChange(of: searchText) { _, _ in visibleCount = 14 }
        .onChange(of: selectedCategory) { _, _ in visibleCount = 14 }
        .onChange(of: sortMode) { _, _ in visibleCount = 14 }
    }

    private var header: some View {
        ViewThatFits(in: .horizontal) {
            HStack(alignment: .center, spacing: 18) {
                titleBlock
                Spacer(minLength: 24)
                toolbar
            }

            VStack(alignment: .leading, spacing: 12) {
                titleBlock
                toolbar
            }
        }
    }

    private var titleBlock: some View {
        HStack(spacing: 12) {
            Text(model.text(.navInformation))
                .font(.system(size: 28, weight: .bold))
                .foregroundStyle(AppPalette.text)

            HStack(spacing: 6) {
                if isRefreshing {
                    ProgressView().controlSize(.mini)
                } else {
                    Circle()
                        .fill(model.information?.partial == true ? AppPalette.warning : AppPalette.success)
                        .frame(width: 7, height: 7)
                }
                Text(isRefreshing ? model.uiText("实时更新中") : updateStatus)
                    .font(.caption.weight(.semibold))
                    .foregroundStyle(model.information?.partial == true ? AppPalette.warning : AppPalette.success)
                    .lineLimit(1)
            }
            .padding(.horizontal, 10)
            .frame(height: 28)
            .background((model.information?.partial == true ? AppPalette.warning : AppPalette.success).opacity(0.10))
            .clipShape(Capsule())
        }
    }

    private var toolbar: some View {
        HStack(spacing: 8) {
            HStack(spacing: 8) {
                Image(systemName: "magnifyingglass")
                    .foregroundStyle(AppPalette.textSubtle)
                TextField(model.uiText("搜索资讯关键词"), text: $searchText)
                    .textFieldStyle(.plain)
                    .font(.callout)
                if !searchText.isEmpty {
                    Button { searchText = "" } label: {
                        Image(systemName: "xmark.circle.fill")
                            .foregroundStyle(AppPalette.textSubtle)
                    }
                    .buttonStyle(.plain)
                    .help(model.uiText("清除搜索"))
                }
            }
            .padding(.horizontal, 11)
            .frame(width: 260, height: 36)
            .background(AppPalette.card)
            .overlay {
                RoundedRectangle(cornerRadius: 8, style: .continuous)
                    .stroke(AppPalette.border)
            }
            .clipShape(RoundedRectangle(cornerRadius: 8, style: .continuous))

            Menu {
                ForEach(InformationSortMode.allCases) { mode in
                    Button {
                        sortMode = mode
                    } label: {
                        Label(mode.title(model), systemImage: sortMode == mode ? "checkmark" : mode.icon)
                    }
                }
            } label: {
                Label(sortMode.title(model), systemImage: sortMode.icon)
                    .font(.callout.weight(.medium))
                    .foregroundStyle(AppPalette.text)
                    .padding(.horizontal, 11)
                    .frame(height: 36)
                    .background(AppPalette.card)
                    .overlay {
                        RoundedRectangle(cornerRadius: 8, style: .continuous)
                            .stroke(AppPalette.border)
                    }
                    .clipShape(RoundedRectangle(cornerRadius: 8, style: .continuous))
            }
            .menuStyle(.borderlessButton)
            .fixedSize()

            Button {
                Task { await model.refreshInformation(force: true) }
            } label: {
                Group {
                    if isRefreshing {
                        ProgressView().controlSize(.small)
                    } else {
                        Image(systemName: "arrow.clockwise")
                    }
                }
                .frame(width: 36, height: 36)
                .background(AppPalette.card)
                .overlay {
                    RoundedRectangle(cornerRadius: 8, style: .continuous)
                        .stroke(AppPalette.border)
                }
                .clipShape(RoundedRectangle(cornerRadius: 8, style: .continuous))
            }
            .buttonStyle(.plain)
            .disabled(isRefreshing)
            .help(model.uiText("刷新最新资讯"))
        }
    }

    private var categoryBar: some View {
        ScrollView(.horizontal, showsIndicators: false) {
            HStack(spacing: 7) {
                ForEach(categories) { category in
                    Button {
                        selectedCategory = category.label
                    } label: {
                        HStack(spacing: 6) {
                            Text(category.label)
                            if category.count > 0 {
                                Text("\(category.count)")
                                    .font(.caption2.weight(.semibold))
                                    .foregroundStyle(selectedCategory == category.label ? Color.white.opacity(0.82) : AppPalette.textSubtle)
                            }
                        }
                        .font(.callout.weight(.semibold))
                        .foregroundStyle(selectedCategory == category.label ? Color.white : AppPalette.textMuted)
                        .padding(.horizontal, 12)
                        .frame(height: 34)
                        .background(selectedCategory == category.label ? categoryColor(category.label) : AppPalette.cardMuted)
                        .clipShape(RoundedRectangle(cornerRadius: 7, style: .continuous))
                    }
                    .buttonStyle(.plain)
                }
            }
        }
    }

    private var content: some View {
        HStack(alignment: .top, spacing: 16) {
            newsFeed
                .frame(minWidth: 0, maxWidth: .infinity)
            sideColumn
                .frame(width: 300)
        }
    }

    @ViewBuilder
    private var newsFeed: some View {
        if isRefreshing && model.information == nil {
            VStack(spacing: 12) {
                ProgressView().controlSize(.large)
                Text(model.uiText("正在接入公开安全资讯"))
                    .font(.callout)
                    .foregroundStyle(AppPalette.textMuted)
            }
            .frame(maxWidth: .infinity, minHeight: 260)
        } else if visibleItems.isEmpty {
            ContentUnavailableView(
                model.uiText("未找到匹配资讯"),
                systemImage: "newspaper",
                description: Text(model.uiText("调整分类或搜索关键词"))
            )
            .frame(maxWidth: .infinity, minHeight: 280)
        } else {
            LazyVStack(spacing: 12) {
                if let first = visibleItems.first {
                    FeaturedInformationCard(item: first) { open(first) }
                }
                ForEach(Array(visibleItems.dropFirst())) { item in
                    InformationNewsCard(item: item) { open(item) }
                }
                if filteredItems.count > visibleItems.count {
                    Button {
                        visibleCount += 12
                    } label: {
                        Label(model.uiText("加载更多"), systemImage: "chevron.down")
                            .font(.callout.weight(.semibold))
                            .frame(maxWidth: .infinity, minHeight: 38)
                    }
                    .buttonStyle(.plain)
                    .foregroundStyle(AppPalette.primaryStrong)
                    .background(AppPalette.card)
                    .overlay {
                        RoundedRectangle(cornerRadius: 8, style: .continuous)
                            .stroke(AppPalette.border)
                    }
                    .clipShape(RoundedRectangle(cornerRadius: 8, style: .continuous))
                }
                Text(model.uiText("显示 %d 条，共 %d 条资讯", visibleItems.count, filteredItems.count))
                    .font(.caption)
                    .foregroundStyle(AppPalette.textSubtle)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(.top, 2)
            }
        }
    }

    private var sideColumn: some View {
        VStack(spacing: 14) {
            popularTagsPanel
            latestBriefsPanel
            sourcePanel
        }
    }

    private var popularTagsPanel: some View {
        Panel {
            VStack(alignment: .leading, spacing: 13) {
                Label(model.uiText("热门标签"), systemImage: "number")
                    .font(.headline)
                    .foregroundStyle(AppPalette.text)
                LazyVGrid(columns: [GridItem(.adaptive(minimum: 72), spacing: 7)], alignment: .leading, spacing: 7) {
                    ForEach(model.information?.popularTags ?? []) { tag in
                        Button {
                            searchText = tag.name
                        } label: {
                            Text(tag.name)
                                .font(.caption.weight(.semibold))
                                .foregroundStyle(tagColor(tag.name))
                                .lineLimit(1)
                                .padding(.horizontal, 8)
                                .frame(minHeight: 28)
                                .frame(maxWidth: .infinity)
                                .background(tagColor(tag.name).opacity(0.10))
                                .clipShape(RoundedRectangle(cornerRadius: 6, style: .continuous))
                        }
                        .buttonStyle(.plain)
                    }
                }
            }
        }
    }

    private var latestBriefsPanel: some View {
        Panel {
            VStack(alignment: .leading, spacing: 13) {
                Label(model.uiText("最新快讯"), systemImage: "bolt.fill")
                    .font(.headline)
                    .foregroundStyle(AppPalette.text)
                ForEach(Array((model.information?.briefs ?? []).prefix(5))) { item in
                    Button { open(item) } label: {
                        HStack(alignment: .top, spacing: 9) {
                            Circle()
                                .fill(categoryColor(item.category))
                                .frame(width: 7, height: 7)
                                .padding(.top, 5)
                            VStack(alignment: .leading, spacing: 3) {
                                Text(item.title)
                                    .font(.caption.weight(.semibold))
                                    .foregroundStyle(AppPalette.text)
                                    .multilineTextAlignment(.leading)
                                    .lineLimit(2)
                                Text(relativeTime(item.publishedAt, locale: model.appLanguage.locale))
                                    .font(.caption2)
                                    .foregroundStyle(AppPalette.textSubtle)
                            }
                            Spacer(minLength: 0)
                        }
                        .contentShape(Rectangle())
                    }
                    .buttonStyle(.plain)
                }
            }
        }
    }

    private var sourcePanel: some View {
        Panel {
            VStack(alignment: .leading, spacing: 11) {
                Label(model.uiText("订阅来源"), systemImage: "dot.radiowaves.left.and.right")
                    .font(.headline)
                    .foregroundStyle(AppPalette.text)
                ForEach(model.information?.sources ?? []) { source in
                    VStack(spacing: 8) {
                        HStack(spacing: 9) {
                            ZStack {
                                RoundedRectangle(cornerRadius: 6, style: .continuous)
                                    .fill(sourceColor(source.id).opacity(0.12))
                                Image(systemName: sourceIcon(source.id))
                                    .font(.system(size: 12, weight: .semibold))
                                    .foregroundStyle(sourceColor(source.id))
                            }
                            .frame(width: 30, height: 30)

                            VStack(alignment: .leading, spacing: 2) {
                                Text(source.name)
                                    .font(.caption.weight(.semibold))
                                    .foregroundStyle(AppPalette.text)
                                    .lineLimit(1)
                                Text(
                                    source.status == "error"
                                        ? "\(source.region) · \(model.uiText("暂时不可用"))"
                                        : "\(source.region) · \(model.uiText("%d 条最新资讯", source.itemCount))"
                                )
                                    .font(.caption2)
                                    .foregroundStyle(source.status == "error" ? AppPalette.warning : AppPalette.textSubtle)
                            }
                            Spacer(minLength: 4)
                            if model.busyActions.contains("information-source:\(source.id)") {
                                ProgressView().controlSize(.mini)
                            } else {
                                Toggle("", isOn: Binding(
                                    get: { source.enabled },
                                    set: { enabled in
                                        Task { await model.setInformationSource(id: source.id, enabled: enabled) }
                                    }
                                ))
                                .labelsHidden()
                                .toggleStyle(.switch)
                                .controlSize(.mini)
                            }
                        }
                        if source.id != model.information?.sources.last?.id {
                            Divider().overlay(AppPalette.border.opacity(0.7))
                        }
                    }
                }
            }
        }
    }

    private var categories: [InformationCategory] {
        let loaded = model.information?.categories ?? []
        if loaded.contains(where: { $0.label == selectedCategory }) || selectedCategory == "全部" {
            return loaded
        }
        return [InformationCategory(id: "all", label: "全部", count: model.information?.availableTotal ?? 0)] + loaded
    }

    private var filteredItems: [InformationItem] {
        var result = model.information?.items ?? []
        if selectedCategory != "全部" {
            result = result.filter { $0.category == selectedCategory }
        }
        let query = searchText.trimmingCharacters(in: .whitespacesAndNewlines)
        if !query.isEmpty {
            result = result.filter { item in
                item.title.localizedCaseInsensitiveContains(query)
                    || item.summary.localizedCaseInsensitiveContains(query)
                    || item.sourceName.localizedCaseInsensitiveContains(query)
                    || item.tags.contains { $0.localizedCaseInsensitiveContains(query) }
            }
        }
        switch sortMode {
        case .latest:
            result.sort { $0.publishedAt > $1.publishedAt }
        case .source:
            result.sort {
                $0.sourceName == $1.sourceName ? $0.publishedAt > $1.publishedAt : $0.sourceName < $1.sourceName
            }
        }
        return result
    }

    private var visibleItems: [InformationItem] {
        Array(filteredItems.prefix(visibleCount))
    }

    private var updateStatus: String {
        guard let value = model.information?.updatedAt, !value.isEmpty else {
            return model.uiText("等待更新")
        }
        return model.uiText("实时已更新")
    }

    private func open(_ item: InformationItem) {
        guard let url = URL(string: item.url) else { return }
        openURL(url)
    }
}

private struct FeaturedInformationCard: View {
    @EnvironmentObject private var model: AppModel
    let item: InformationItem
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            HStack(spacing: 16) {
                InformationArtwork(item: item)
                    .informationArtworkFrame(width: 220, height: 150)
                bodyContent
            }
            .padding(16)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(AppPalette.selectedStrong.opacity(0.66))
            .overlay {
                RoundedRectangle(cornerRadius: 8, style: .continuous)
                    .stroke(AppPalette.primary.opacity(0.24))
            }
            .clipShape(RoundedRectangle(cornerRadius: 8, style: .continuous))
            .contentShape(RoundedRectangle(cornerRadius: 8, style: .continuous))
        }
        .buttonStyle(.plain)
        .help(model.uiText("在浏览器中打开"))
    }

    private var bodyContent: some View {
        VStack(alignment: .leading, spacing: 9) {
            HStack(spacing: 7) {
                if item.breaking {
                    InformationBadge(text: model.uiText("快讯"), color: AppPalette.danger)
                }
                InformationBadge(text: item.category, color: categoryColor(item.category))
                Text(relativeTime(item.publishedAt, locale: model.appLanguage.locale))
                    .font(.caption2)
                    .foregroundStyle(AppPalette.textSubtle)
            }
            Text(item.title)
                .font(.title3.weight(.bold))
                .foregroundStyle(AppPalette.text)
                .multilineTextAlignment(.leading)
                .lineLimit(3)
            if !item.summary.isEmpty {
                Text(item.summary)
                    .font(.callout)
                    .foregroundStyle(AppPalette.textMuted)
                    .multilineTextAlignment(.leading)
                    .lineLimit(3)
            }
            Spacer(minLength: 0)
            InformationSourceLine(item: item)
        }
        .frame(maxWidth: .infinity, minHeight: 132, alignment: .leading)
    }
}

private struct InformationNewsCard: View {
    @EnvironmentObject private var model: AppModel
    let item: InformationItem
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            HStack(alignment: .center, spacing: 14) {
                InformationArtwork(item: item)
                    .informationArtworkFrame(width: 164, height: 108)
                VStack(alignment: .leading, spacing: 7) {
                    HStack(spacing: 7) {
                        InformationBadge(text: item.category, color: categoryColor(item.category))
                        Text(relativeTime(item.publishedAt, locale: model.appLanguage.locale))
                            .font(.caption2)
                            .foregroundStyle(AppPalette.textSubtle)
                    }
                    Text(item.title)
                        .font(.headline)
                        .foregroundStyle(AppPalette.text)
                        .multilineTextAlignment(.leading)
                        .lineLimit(2)
                    if !item.summary.isEmpty {
                        Text(item.summary)
                            .font(.caption)
                            .foregroundStyle(AppPalette.textMuted)
                            .multilineTextAlignment(.leading)
                            .lineLimit(2)
                    }
                    InformationSourceLine(item: item)
                }
                .frame(maxWidth: .infinity, minHeight: 108, alignment: .leading)
            }
            .padding(13)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(AppPalette.card)
            .overlay {
                RoundedRectangle(cornerRadius: 8, style: .continuous)
                    .stroke(AppPalette.border.opacity(0.9))
            }
            .clipShape(RoundedRectangle(cornerRadius: 8, style: .continuous))
            .contentShape(RoundedRectangle(cornerRadius: 8, style: .continuous))
        }
        .buttonStyle(.plain)
        .help(model.uiText("在浏览器中打开"))
    }
}

private extension View {
    func informationArtworkFrame(width: CGFloat, height: CGFloat) -> some View {
        frame(width: width, height: height)
            .clipped()
            .clipShape(RoundedRectangle(cornerRadius: 7, style: .continuous))
    }
}

private struct InformationArtwork: View {
    @EnvironmentObject private var model: AppModel
    let item: InformationItem
    @State private var loadedImage: NSImage?
    @State private var loadedSourceFallback = false

    var body: some View {
        Group {
            if let loadedImage {
                if loadedSourceFallback {
                    sourceArtwork(loadedImage)
                } else {
                    Image(nsImage: loadedImage)
                        .resizable()
                        .scaledToFill()
                }
            } else {
                placeholder
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .clipped()
        .background(categoryColor(item.category).opacity(0.10))
        .clipShape(RoundedRectangle(cornerRadius: 7, style: .continuous))
        .task(id: imageRequestKey) {
            await loadImage()
        }
    }

    private var placeholder: some View {
        ZStack {
            categoryColor(item.category).opacity(0.12)
            Image(systemName: categoryIcon(item.category))
                .font(.system(size: 30, weight: .medium))
                .foregroundStyle(categoryColor(item.category).opacity(0.82))
        }
    }

    private func sourceArtwork(_ image: NSImage) -> some View {
        ZStack {
            categoryColor(item.category).opacity(0.10)
            VStack(spacing: 9) {
                Image(nsImage: image)
                    .resizable()
                    .scaledToFit()
                    .frame(maxWidth: 86, maxHeight: 48)
                Text(item.sourceName)
                    .font(.caption2.weight(.semibold))
                    .foregroundStyle(AppPalette.textMuted)
                    .lineLimit(1)
            }
            .padding(18)
        }
    }

    private var imageRequestKey: String {
        "\(model.serverURL)|\(item.id)|\(item.imageUrl)|\(item.sourceImageUrl ?? "")"
    }

    private func loadImage() async {
        await MainActor.run {
            loadedImage = nil
            loadedSourceFallback = false
        }
        guard
            let baseURL = URL(string: model.serverURL),
            let itemID = item.id.addingPercentEncoding(withAllowedCharacters: .urlPathAllowed)
        else { return }
        let url = baseURL.appending(path: "api/information/images/\(itemID)")
        guard !Task.isCancelled else { return }
        if let cached = InformationImageCache.shared.object(forKey: url as NSURL) {
            await MainActor.run {
                loadedImage = cached.image
                loadedSourceFallback = cached.sourceFallback
            }
            return
        }
        var request = URLRequest(url: url, cachePolicy: .returnCacheDataElseLoad, timeoutInterval: 20)
        request.setValue("image/avif,image/webp,image/png,image/jpeg,image/*;q=0.8", forHTTPHeaderField: "Accept")
        do {
            let (data, response) = try await URLSession.shared.data(for: request)
            guard
                let http = response as? HTTPURLResponse,
                (200..<300).contains(http.statusCode),
                data.count <= 8_000_000,
                let image = NSImage(data: data)
            else { return }
            let sourceFallback = http.value(forHTTPHeaderField: "X-SecFlow-Image-Kind") == "source"
            let cached = InformationCachedImage(image: image, sourceFallback: sourceFallback)
            InformationImageCache.shared.setObject(cached, forKey: url as NSURL, cost: data.count)
            guard !Task.isCancelled else { return }
            await MainActor.run {
                loadedImage = image
                loadedSourceFallback = sourceFallback
            }
        } catch {
            return
        }
    }
}

private final class InformationCachedImage {
    let image: NSImage
    let sourceFallback: Bool

    init(image: NSImage, sourceFallback: Bool) {
        self.image = image
        self.sourceFallback = sourceFallback
    }
}

private enum InformationImageCache {
    static let shared: NSCache<NSURL, InformationCachedImage> = {
        let cache = NSCache<NSURL, InformationCachedImage>()
        cache.countLimit = 120
        cache.totalCostLimit = 96 * 1_024 * 1_024
        return cache
    }()
}

private struct InformationSourceLine: View {
    let item: InformationItem

    var body: some View {
        HStack(spacing: 7) {
            Circle()
                .fill(sourceColor(item.sourceId))
                .frame(width: 20, height: 20)
                .overlay {
                    Image(systemName: sourceIcon(item.sourceId))
                        .font(.system(size: 9, weight: .bold))
                        .foregroundStyle(.white)
                }
            Text(item.sourceName)
                .font(.caption.weight(.semibold))
                .foregroundStyle(AppPalette.textMuted)
                .lineLimit(1)
            if !item.author.isEmpty, item.author != item.sourceName {
                Text("· \(item.author)")
                    .font(.caption)
                    .foregroundStyle(AppPalette.textSubtle)
                    .lineLimit(1)
            }
        }
    }
}

private struct InformationBadge: View {
    let text: String
    let color: Color

    var body: some View {
        Text(text)
            .font(.caption2.weight(.bold))
            .foregroundStyle(color)
            .padding(.horizontal, 7)
            .frame(height: 22)
            .background(color.opacity(0.11))
            .clipShape(RoundedRectangle(cornerRadius: 5, style: .continuous))
    }
}

private enum InformationSortMode: String, CaseIterable, Identifiable {
    case latest
    case source

    var id: String { rawValue }
    var icon: String { self == .latest ? "clock" : "square.stack.3d.up" }

    @MainActor func title(_ model: AppModel) -> String {
        self == .latest ? model.uiText("最新发布") : model.uiText("按来源")
    }
}

private func relativeTime(_ value: String, locale: Locale) -> String {
    guard let date = informationDate(value) else { return value }
    let formatter = RelativeDateTimeFormatter()
    formatter.locale = locale
    formatter.unitsStyle = .short
    return formatter.localizedString(for: date, relativeTo: Date())
}

private func informationDate(_ value: String) -> Date? {
    let formatter = ISO8601DateFormatter()
    formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
    if let date = formatter.date(from: value) { return date }
    formatter.formatOptions = [.withInternetDateTime]
    return formatter.date(from: value)
}

private func categoryColor(_ category: String) -> Color {
    switch category {
    case "全部": return AppPalette.primaryStrong
    case "AI 安全": return AppPalette.primaryStrong
    case "大模型": return Color(red: 0.55, green: 0.28, blue: 0.82)
    case "漏洞披露": return AppPalette.danger
    case "数据安全": return AppPalette.success
    case "政策法规": return Color(red: 0.63, green: 0.31, blue: 0.76)
    case "云安全": return Color(red: 0.13, green: 0.45, blue: 0.82)
    case "供应链安全": return Color(red: 0.89, green: 0.48, blue: 0.10)
    case "攻击技术": return AppPalette.warning
    default: return AppPalette.textMuted
    }
}

private func categoryIcon(_ category: String) -> String {
    switch category {
    case "AI 安全": return "brain.head.profile"
    case "大模型": return "sparkles"
    case "漏洞披露": return "shield.lefthalf.filled.badge.checkmark"
    case "数据安全": return "externaldrive.fill.badge.checkmark"
    case "政策法规": return "building.columns.fill"
    case "云安全": return "cloud.fill"
    case "供应链安全": return "shippingbox.fill"
    case "攻击技术": return "scope"
    default: return "newspaper.fill"
    }
}

private func sourceColor(_ sourceID: String) -> Color {
    switch sourceID {
    case "cisa_advisories", "cisa_kev": return AppPalette.danger
    case "freebuf": return AppPalette.primaryStrong
    case "aliyun_xz": return Color(red: 0.96, green: 0.43, blue: 0.08)
    case "tencent_security", "tencent_xlab": return Color(red: 0.00, green: 0.48, blue: 0.78)
    case "microsoft_security": return Color(red: 0.00, green: 0.47, blue: 0.74)
    case "talos": return Color(red: 0.96, green: 0.55, blue: 0.04)
    case "portswigger_research": return Color(red: 0.88, green: 0.31, blue: 0.08)
    case "sans_isc": return AppPalette.warning
    default: return AppPalette.primaryStrong
    }
}

private func sourceIcon(_ sourceID: String) -> String {
    switch sourceID {
    case "cisa_advisories", "cisa_kev": return "shield.fill"
    case "freebuf": return "newspaper.fill"
    case "aliyun_xz": return "cloud.fill"
    case "tencent_security", "tencent_xlab": return "shield.lefthalf.filled"
    case "microsoft_security": return "building.2.fill"
    case "talos": return "scope"
    case "portswigger_research": return "flask.fill"
    case "sans_isc": return "waveform.path.ecg"
    default: return "network"
    }
}

private func tagColor(_ tag: String) -> Color {
    let palette: [Color] = [
        AppPalette.primaryStrong,
        AppPalette.danger,
        AppPalette.warning,
        AppPalette.success,
        Color(red: 0.55, green: 0.28, blue: 0.82),
        Color(red: 0.13, green: 0.45, blue: 0.82),
    ]
    return palette[abs(tag.hashValue) % palette.count]
}
