import AppKit
import SwiftUI
import UniformTypeIdentifiers

private let allowedCodeAttachmentExtensions: Set<String> = [
    "java", "kt", "kts", "scala", "groovy",
    "py",
    "js", "jsx", "ts", "tsx",
    "go", "rs", "php", "rb", "cs",
    "c", "cc", "cpp", "cxx", "h", "hh", "hpp", "hxx",
    "swift", "m", "mm",
    "sol",
]

private let allowedProjectManifestFileNames: Set<String> = [
    "gradle.properties",
    "libs.versions.toml",
    "requirements.txt", "pyproject.toml", "pipfile", "poetry.lock",
    "go.mod", "go.sum",
    "cmakelists.txt", "conanfile.txt", "conanfile.py", "vcpkg.json",
    "cargo.toml", "cargo.lock",
    "foundry.toml", "remappings.txt", "package.json",
    "hardhat.config.js", "hardhat.config.ts", "truffle-config.js",
]

private let allowedGradleAttachmentExtensions: Set<String> = [
    "gradle",
    "toml",
]

private let allowedAttachmentContentTypes: [UTType] = {
    var types: [UTType] = [.folder, .plainText, .sourceCode]
    for ext in (["xml", "json", "lock", "mod", "sum", "txt"] + Array(allowedGradleAttachmentExtensions) + Array(allowedCodeAttachmentExtensions)).sorted() {
        if let type = UTType(filenameExtension: ext) {
            types.append(type)
        }
    }
    return types
}()

private let maxAssistantAttachments = 300
private let maxAssistantAttachmentCharacters = 120_000
private let maxAssistantAttachmentTotalCharacters = 6_000_000
private let skippedProjectDirectoryNames: Set<String> = [
    ".git", ".gradle", ".idea", ".mvn", ".svn", ".hg",
    "build", "target", "dist", "out", "generated",
    "node_modules", ".next", ".nuxt",
    ".venv", "venv", "__pycache__", ".pytest_cache",
    "coverage", ".nyc_output",
]

func isMeaningfulAssistantQuestion(_ value: String) -> Bool {
    value.unicodeScalars.contains { CharacterSet.alphanumerics.contains($0) }
}

struct AssistantView: View {
    @EnvironmentObject private var model: AppModel
    @State private var question = ""
    @State private var isImporting = false
    @State private var isDropTargeted = false
    @State private var attachments: [AskAttachmentPayload] = []
    @State private var askTask: Task<Void, Never>?

    var body: some View {
        VStack(spacing: 0) {
            header
            conversation
            composer
        }
        .background(AppPalette.page)
        .foregroundStyle(AppPalette.text)
        .fileImporter(
            isPresented: $isImporting,
            allowedContentTypes: allowedAttachmentContentTypes,
            allowsMultipleSelection: true,
            onCompletion: importAttachment
        )
    }

    private var header: some View {
        HStack(spacing: 16) {
            Text(model.uiText("智能问答"))
                .font(.title2.weight(.bold))
                .foregroundStyle(AppPalette.text)

            Spacer()

            Button {
                model.startNewConversation()
                question = ""
                clearAttachments()
            } label: {
                Label(model.uiText("新对话"), systemImage: "plus")
                    .font(.callout.weight(.semibold))
                    .padding(.horizontal, 8)
                    .frame(height: 36)
            }
            .buttonStyle(PrimaryActionButtonStyle())
            .clipShape(RoundedRectangle(cornerRadius: 7, style: .continuous))
            .help(model.uiText("新建对话"))
        }
        .padding(.horizontal, 30)
        .frame(height: 72)
        .background(AppPalette.page)
    }

    private var conversation: some View {
        ScrollViewReader { proxy in
            ScrollView {
                LazyVStack(spacing: 24) {
                    if model.conversationTurns.isEmpty && !model.isAsking {
                        Color.clear.frame(height: 260)
                    }

                    ForEach(model.conversationTurns) { turn in
                        UserBubble(turn: turn)

                        if let answer = turn.answer {
                            AssistantBubble(answer: answer, timestamp: turn.answeredAt ?? turn.askedAt)
                        } else if let error = turn.errorMessage {
                            AssistantErrorBubble(message: error, timestamp: turn.answeredAt ?? turn.askedAt)
                        } else {
                            AssistantLoadingBubble(startedAt: turn.askedAt)
                        }
                    }

                    Color.clear.frame(height: 1).id("conversation-bottom")
                }
                .padding(.horizontal, 30)
                .padding(.top, 12)
                .padding(.bottom, 20)
                .frame(maxWidth: 1160)
                .frame(maxWidth: .infinity)
            }
            .onChange(of: model.conversationTurns.count) { _, _ in
                withAnimation(.easeOut(duration: 0.2)) {
                    proxy.scrollTo("conversation-bottom", anchor: .bottom)
                }
            }
            .onChange(of: model.isAsking) { _, _ in
                withAnimation(.easeOut(duration: 0.2)) {
                    proxy.scrollTo("conversation-bottom", anchor: .bottom)
                }
            }
            .textSelection(.enabled)
        }
    }

    private var composer: some View {
        VStack(spacing: 10) {
            if !attachments.isEmpty {
                ScrollView(.horizontal, showsIndicators: false) {
                    HStack(spacing: 8) {
                        ForEach(attachments, id: \.fileName) { attachment in
                            AttachmentChip(attachment: attachment) {
                                removeAttachment(named: attachment.fileName)
                            }
                        }
                    }
                    .padding(.vertical, 1)
                }
                .frame(maxWidth: 1080)
            }

            HStack(alignment: .bottom, spacing: 13) {
                Button {
                    isImporting = true
                } label: {
                    Image(systemName: "paperclip")
                        .font(.system(size: 17, weight: .medium))
                        .frame(width: 28, height: 32)
                }
                .buttonStyle(.plain)
                .foregroundStyle(AppPalette.textMuted)
                .help(model.uiText("添加项目清单、代码附件或完整项目目录"))

                TextField(model.uiText("输入安全问题，获取智能分析…"), text: $question, axis: .vertical)
                    .textFieldStyle(.plain)
                    .font(.callout)
                    .foregroundStyle(AppPalette.text)
                    .lineLimit(1...4)
                    .padding(.vertical, 8)
                    .onSubmit(submit)

                Button(action: model.isAsking ? cancelCurrentRequest : submit) {
                    Image(systemName: model.isAsking ? "stop.fill" : "paperplane.fill")
                        .foregroundStyle(.white)
                        .frame(width: 34, height: 34)
                        .background(AppPalette.primary)
                        .clipShape(RoundedRectangle(cornerRadius: 7, style: .continuous))
                }
                .buttonStyle(.plain)
                .disabled(!model.isAsking && !canSubmit)
                .opacity(model.isAsking || canSubmit ? 1 : 0.45)
                .help(model.isAsking ? model.uiText("停止生成") : model.uiText("发送"))
            }
            .padding(.horizontal, 16)
            .padding(.vertical, 8)
            .frame(minHeight: 66)
            .background(AppPalette.card)
            .clipShape(RoundedRectangle(cornerRadius: 12, style: .continuous))
            .overlay {
                RoundedRectangle(cornerRadius: 12, style: .continuous)
                    .stroke(
                        isDropTargeted ? AppPalette.primary : AppPalette.border,
                        lineWidth: isDropTargeted ? 1.5 : 1
                    )
            }
            .background {
                if isDropTargeted {
                    RoundedRectangle(cornerRadius: 12, style: .continuous)
                        .fill(AppPalette.primary.opacity(0.08))
                }
            }
            .onDrop(
                of: [UTType.fileURL.identifier],
                isTargeted: $isDropTargeted,
                perform: handleAttachmentDrop
            )
            .frame(maxWidth: 1100)

            HStack(spacing: 5) {
                Image(systemName: isDropTargeted ? "arrow.down.doc.fill" : "info.circle")
                Text(isDropTargeted ? model.uiText("松开即可添加项目或附件") : model.uiText("支持拖入 Python、Go、C/C++、Rust、Solidity、Java 项目；会自动忽略构建产物目录"))
            }
            .font(.caption2)
            .foregroundStyle(AppPalette.textMuted)
        }
        .padding(.horizontal, 30)
        .padding(.bottom, 14)
        .background(AppPalette.page)
    }

    private var canSubmit: Bool {
        (isMeaningfulAssistantQuestion(question) || !attachments.isEmpty)
            && !model.isAsking
    }

    private func submit() {
        let visibleQuestion = question.trimmingCharacters(in: .whitespacesAndNewlines)
        guard canSubmit else {
            if !visibleQuestion.isEmpty && attachments.isEmpty {
                model.errorMessage = model.uiText("请输入包含文字或数字的具体安全问题")
            }
            return
        }

        let displayText: String
        if !isMeaningfulAssistantQuestion(visibleQuestion) {
            displayText = attachmentPromptText
        } else {
            displayText = visibleQuestion
        }
        let submittedAttachments = attachments

        let turn = ConversationTurn(
            question: displayText,
            attachmentNames: submittedAttachments.map(\.fileName)
        )
        model.conversationTurns.append(turn)
        question = ""
        clearAttachments()

        askTask = Task { @MainActor in
            defer { askTask = nil }
            let result = await model.ask(question: displayText, topK: 8, attachments: submittedAttachments)
            guard let index = model.conversationTurns.firstIndex(where: { $0.id == turn.id }) else { return }
            model.conversationTurns[index].answeredAt = Date()
            if let result {
                model.conversationTurns[index].answer = result
            } else {
                model.conversationTurns[index].errorMessage = model.errorMessage ?? model.uiText("本地安全分析暂时不可用。")
            }
        }
    }

    private func cancelCurrentRequest() {
        askTask?.cancel()
    }

    private func importAttachment(_ result: Result<[URL], Error>) {
        do {
            let urls = try result.get()
            guard !urls.isEmpty else { return }
            var summary = AttachmentImportSummary()
            for url in urls {
                try importAttachmentURL(url, summary: &summary)
            }
            applyImportSummary(summary)
        } catch {
            model.errorMessage = model.uiText("附件读取失败：%@", error.localizedDescription)
        }
    }

    private func handleAttachmentDrop(_ providers: [NSItemProvider]) -> Bool {
        let fileProviders = providers.filter { $0.hasItemConformingToTypeIdentifier(UTType.fileURL.identifier) }
        guard !fileProviders.isEmpty else {
            model.errorMessage = model.uiText("请拖入项目清单或代码文件")
            return false
        }

        for provider in fileProviders.prefix(maxAssistantAttachments) {
            provider.loadItem(forTypeIdentifier: UTType.fileURL.identifier, options: nil) { item, error in
                DispatchQueue.main.async {
                    if let error {
                        model.errorMessage = model.uiText("附件读取失败：%@", error.localizedDescription)
                        return
                    }
                    guard let url = droppedFileURL(from: item) else {
                        model.errorMessage = model.uiText("无法识别拖入的文件")
                        return
                    }
                    do {
                        var summary = AttachmentImportSummary()
                        try importAttachmentURL(url, summary: &summary)
                        applyImportSummary(summary)
                    } catch {
                        model.errorMessage = model.uiText("附件读取失败：%@", error.localizedDescription)
                    }
                }
            }
        }
        return true
    }

    private func importAttachmentURL(_ url: URL, summary: inout AttachmentImportSummary) throws {
        let scoped = url.startAccessingSecurityScopedResource()
        defer { if scoped { url.stopAccessingSecurityScopedResource() } }

        let values = try url.resourceValues(forKeys: [.isDirectoryKey, .isRegularFileKey, .isSymbolicLinkKey])
        if values.isSymbolicLink == true {
            summary.skippedUnsupported += 1
            return
        }

        if values.isDirectory == true {
            try importProjectDirectory(url, summary: &summary)
            return
        }

        guard values.isRegularFile == true else {
            summary.skippedUnsupported += 1
            return
        }

        try importAttachmentFile(url, fileName: url.lastPathComponent, summary: &summary)
    }

    private func importProjectDirectory(_ directory: URL, summary: inout AttachmentImportSummary) throws {
        let candidates = try projectAttachmentCandidates(in: directory)
        if candidates.isEmpty {
            summary.skippedUnsupported += 1
            return
        }

        for (index, fileURL) in candidates.enumerated() {
            let relativePath = projectRelativePath(for: fileURL, root: directory)
            try importAttachmentFile(fileURL, fileName: relativePath, summary: &summary)
            if attachments.count >= maxAssistantAttachments {
                summary.skippedLimit += max(0, candidates.count - index - 1)
                break
            }
        }
    }

    private func importAttachmentFile(_ url: URL, fileName: String, summary: inout AttachmentImportSummary) throws {
        guard isAllowedAttachmentURL(url) else {
            summary.skippedUnsupported += 1
            return
        }
        let existingIndex = attachments.firstIndex { $0.fileName == fileName }
        guard existingIndex != nil || attachments.count < maxAssistantAttachments else {
            summary.skippedLimit += 1
            return
        }
        let data = try Data(contentsOf: url)
        guard let content = String(data: data, encoding: .utf8) else {
            throw CocoaError(.fileReadInapplicableStringEncoding)
        }
        let truncatedContent = String(content.prefix(maxAssistantAttachmentCharacters))
        let currentTotal = attachments.reduce(0) { $0 + $1.content.count }
        let replacedCount = existingIndex.map { attachments[$0].content.count } ?? 0
        guard currentTotal - replacedCount + truncatedContent.count <= maxAssistantAttachmentTotalCharacters else {
            summary.skippedLarge += 1
            return
        }
        let nextAttachment = AskAttachmentPayload(
            fileName: fileName,
            content: truncatedContent,
            mimeType: nil
        )
        if let existingIndex {
            attachments[existingIndex] = nextAttachment
            summary.updated += 1
        } else {
            attachments.append(nextAttachment)
            summary.imported += 1
        }
    }

    private func isAllowedAttachmentURL(_ url: URL) -> Bool {
        let fileName = url.lastPathComponent.lowercased()
        if fileName == "pom.xml" || allowedProjectManifestFileNames.contains(fileName) {
            return true
        }
        if fileName.hasSuffix(".gradle") || fileName.hasSuffix(".gradle.kts") {
            return true
        }
        return allowedCodeAttachmentExtensions.contains(url.pathExtension.lowercased())
    }

    private func projectAttachmentCandidates(in directory: URL) throws -> [URL] {
        let keys: [URLResourceKey] = [.isDirectoryKey, .isRegularFileKey, .isSymbolicLinkKey]
        guard let enumerator = FileManager.default.enumerator(
            at: directory,
            includingPropertiesForKeys: keys,
            options: [.skipsHiddenFiles, .skipsPackageDescendants]
        ) else {
            throw CocoaError(.fileReadUnknown)
        }

        var candidates: [URL] = []
        for case let fileURL as URL in enumerator {
            let values = try fileURL.resourceValues(forKeys: Set(keys))
            if values.isSymbolicLink == true {
                continue
            }
            if values.isDirectory == true {
                if shouldSkipProjectDirectory(fileURL) {
                    enumerator.skipDescendants()
                }
                continue
            }
            guard values.isRegularFile == true, isAllowedAttachmentURL(fileURL) else {
                continue
            }
            candidates.append(fileURL)
        }

        return candidates.sorted { left, right in
            let leftPriority = projectAttachmentPriority(left)
            let rightPriority = projectAttachmentPriority(right)
            if leftPriority != rightPriority {
                return leftPriority < rightPriority
            }
            return left.path.localizedStandardCompare(right.path) == .orderedAscending
        }
    }

    private func shouldSkipProjectDirectory(_ url: URL) -> Bool {
        skippedProjectDirectoryNames.contains(url.lastPathComponent.lowercased())
    }

    private func projectAttachmentPriority(_ url: URL) -> Int {
        let fileName = url.lastPathComponent.lowercased()
        if fileName == "pom.xml" {
            return 0
        }
        if allowedProjectManifestFileNames.contains(fileName) || fileName.hasSuffix(".gradle") || fileName.hasSuffix(".gradle.kts") {
            return 0
        }
        if url.pathExtension.lowercased() == "java" {
            return 1
        }
        return 2
    }

    private func projectRelativePath(for fileURL: URL, root: URL) -> String {
        let rootPath = root.standardizedFileURL.path
        let filePath = fileURL.standardizedFileURL.path
        let relative: String
        if filePath.hasPrefix(rootPath + "/") {
            relative = String(filePath.dropFirst(rootPath.count + 1))
        } else {
            relative = fileURL.lastPathComponent
        }
        return "\(root.lastPathComponent)/\(relative)".replacingOccurrences(of: "\\", with: "/")
    }

    private func applyImportSummary(_ summary: AttachmentImportSummary) {
        if summary.imported == 0 && summary.updated == 0 {
            if summary.skippedLimit > 0 {
                model.errorMessage = model.uiText("最多支持添加 %d 个项目文件", maxAssistantAttachments)
            } else if summary.skippedLarge > 0 {
                model.errorMessage = model.uiText("项目文件内容过大，已超过本次分析的上传上限")
            } else {
                model.errorMessage = model.uiText("未找到可分析的项目清单或代码文件")
            }
            return
        }
        model.errorMessage = nil
    }

    private var attachmentPromptText: String {
        if attachments.count == 1 {
            return model.uiText("请分析附件 %@", attachments[0].fileName)
        }
        let names = attachments.map(\.fileName).joined(separator: "、")
        return model.uiText("请分析 %d 个附件：%@", attachments.count, names)
    }

    private func removeAttachment(named fileName: String) {
        attachments.removeAll { $0.fileName == fileName }
    }

    private func clearAttachments() {
        attachments = []
    }
}

private struct AttachmentImportSummary {
    var imported = 0
    var updated = 0
    var skippedUnsupported = 0
    var skippedLimit = 0
    var skippedLarge = 0
}

private func droppedFileURL(from item: NSSecureCoding?) -> URL? {
    if let url = item as? URL {
        return url
    }
    if let url = item as? NSURL {
        return url as URL
    }
    if let data = item as? Data, let text = String(data: data, encoding: .utf8) {
        return URL(string: text.trimmingCharacters(in: .whitespacesAndNewlines))
    }
    if let text = item as? String {
        let cleanText = text.trimmingCharacters(in: .whitespacesAndNewlines)
        return URL(string: cleanText) ?? URL(fileURLWithPath: cleanText)
    }
    return nil
}

private struct AttachmentChip: View {
    @EnvironmentObject private var model: AppModel
    let attachment: AskAttachmentPayload
    let onRemove: () -> Void

    var body: some View {
        HStack(spacing: 7) {
            Image(systemName: "doc.text")
            Text(attachment.fileName)
                .lineLimit(1)
                .truncationMode(.middle)
                .frame(maxWidth: 260)
            Button(action: onRemove) {
                Image(systemName: "xmark.circle.fill")
                    .font(.system(size: 12, weight: .semibold))
            }
            .buttonStyle(.plain)
            .help(model.uiText("移除附件"))
        }
        .font(.caption.weight(.semibold))
        .foregroundStyle(AppPalette.textMuted)
        .padding(.horizontal, 10)
        .padding(.vertical, 6)
        .background(AppPalette.card)
        .clipShape(RoundedRectangle(cornerRadius: 8, style: .continuous))
        .overlay {
            RoundedRectangle(cornerRadius: 8, style: .continuous)
                .stroke(AppPalette.border)
        }
    }
}

private struct UserBubble: View {
    let turn: ConversationTurn

    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            Spacer(minLength: 150)
            VStack(alignment: .trailing, spacing: 5) {
                VStack(alignment: .leading, spacing: 7) {
                    Text(turn.question)
                        .textSelection(.enabled)
                    if !turn.attachmentNames.isEmpty {
                        VStack(alignment: .leading, spacing: 5) {
                            ForEach(turn.attachmentNames, id: \.self) { attachmentName in
                                Label(attachmentName, systemImage: "doc.text")
                                    .font(.caption)
                                    .lineLimit(1)
                                    .padding(.horizontal, 8)
                                    .padding(.vertical, 5)
                                    .background(Color.white.opacity(0.16))
                                    .clipShape(RoundedRectangle(cornerRadius: 5))
                            }
                        }
                    }
                }
                .font(.callout.weight(.medium))
                .foregroundStyle(.white)
                .padding(.horizontal, 18)
                .padding(.vertical, 13)
                .background(AppPalette.primary)
                .clipShape(RoundedRectangle(cornerRadius: 16, style: .continuous))

                Text(turn.askedAt.chatTime)
                    .font(.caption2)
                    .foregroundStyle(AppPalette.textMuted)
            }
            Text("李")
                .font(.caption.weight(.bold))
                .foregroundStyle(.white)
                .frame(width: 32, height: 32)
                .background(AppPalette.primary)
                .clipShape(Circle())
        }
    }
}

private struct AssistantBubble: View {
    @EnvironmentObject private var model: AppModel
    let answer: AskResult
    let timestamp: Date

    var body: some View {
        HStack(alignment: .top, spacing: 12) {
            AssistantAvatar()
            VStack(alignment: .leading, spacing: 10) {
                VStack(alignment: .leading, spacing: 12) {
                    if answer.mode == "dependency_vulnerability_report" {
                        RichAnswerText(text: answer.summary)
                        if let chartData = answer.chartData, chartData.hasContent {
                            Divider()
                            DependencyChartsView(chartData: chartData)
                        }
                        if let card = answer.vulnerabilityCard, !card.isEmpty {
                            Divider()
                            vulnerabilityReport(card)
                        }
                    } else if let card = answer.vulnerabilityCard, !card.isEmpty {
                        vulnerabilityReport(card)
                    } else {
                        RichAnswerText(text: answer.summary)
                    }
                }
                .padding(18)
                .frame(maxWidth: answer.chartData?.hasContent == true ? 980 : 690, alignment: .leading)
                .background(AppPalette.card)
                .clipShape(RoundedRectangle(cornerRadius: 14, style: .continuous))
                .textSelection(.enabled)

                HStack(alignment: .center) {
                    MessageActions(text: answer.summary)
                    Spacer()
                    Text(timestamp.chatTime)
                        .font(.caption2)
                        .foregroundStyle(AppPalette.textMuted)
                }
            }
            .frame(maxWidth: answer.chartData?.hasContent == true ? 980 : 690, alignment: .leading)
            Spacer(minLength: 120)
        }
    }

    @ViewBuilder
    private func vulnerabilityReport(_ card: [String: String]) -> some View {
        Text(model.uiText("%@ 漏洞分析报告", card["漏洞编号"] ?? model.uiText("漏洞")))
            .font(.headline)
        Divider()

        VulnerabilityDescriptionField(
            value: card["漏洞描述"] ?? answer.summary,
            score: card["CVSS评分"],
            severity: card["严重等级"]
        )

        VStack(alignment: .leading, spacing: 6) {
            if !componentNodes.isEmpty {
                Text(model.uiText("根据知识图谱分析，您的系统中以下组件可能受到影响："))
            }
        }
        .font(.callout)

        VStack(spacing: 8) {
            if let value = normalizedCardValue("组件版本范围", from: card) {
                VulnerabilityReportField(title: model.uiText("组件版本范围"), value: value, icon: "shippingbox", tone: AppPalette.primary)
            }
            if let value = normalizedCardValue("涉及版本", from: card) {
                VulnerabilityReportField(title: model.uiText("涉及版本"), value: value, icon: "exclamationmark.triangle", tone: AppPalette.warning)
            }
            if let value = normalizedCardValue("修复版本", from: card) {
                VulnerabilityReportField(title: model.uiText("修复版本"), value: value, icon: "checkmark.shield", tone: AppPalette.success)
            }
        }

        ForEach(Array(componentNodes.prefix(5).enumerated()), id: \.element.id) { index, node in
            ImpactComponentRow(node: node, critical: index == 0)
        }

        if let solution = card["修复方案"], !solution.isEmpty {
            VulnerabilityReportField(title: model.uiText("修复方案"), value: solution, icon: "wrench.and.screwdriver", tone: AppPalette.success)
        }

        if let mitigation = card["缓释措施"], !mitigation.isEmpty {
            VulnerabilityReportField(title: model.uiText("缓释措施"), value: mitigation, icon: "shield.lefthalf.filled", tone: AppPalette.warning)
        }

        if let references = normalizedCardValue("参考链接", from: card) {
            VulnerabilityReferenceLinks(value: references)
        }

        if let code = normalizedCardValue("代码片段", from: card) {
            VulnerabilityCodeSnippet(title: model.uiText("代码片段"), code: code, tone: AppPalette.danger)
        }

        if let fixedCode = normalizedCardValue("修复代码片段", from: card) {
            VulnerabilityCodeSnippet(title: model.uiText("修复代码片段"), code: fixedCode, tone: AppPalette.success)
        }
    }

    private var componentNodes: [KnowledgeNode] {
        answer.knowledgeGraph?.nodes.filter { $0.type == "component" } ?? []
    }

    private func normalizedCardValue(_ key: String, from card: [String: String]) -> String? {
        guard let value = card[key]?.trimmingCharacters(in: .whitespacesAndNewlines),
              !value.isEmpty,
              !isPlaceholderCardValue(value)
        else {
            return nil
        }
        return value
    }

    private func isPlaceholderCardValue(_ value: String) -> Bool {
        let normalized = value.trimmingCharacters(in: .whitespacesAndNewlines)
        return [
            "未明确",
            "未知",
            "Not specified",
            "Unknown",
            "未指定",
            "不明",
            "명확하지 않음",
            "알 수 없음",
            "未在漏洞记录中找到可核验代码片段",
            "未在漏洞记录中找到可核验修复代码片段",
            "No verifiable code snippet was found in the vulnerability record",
            "No verifiable fixed code snippet was found in the vulnerability record",
            "脆弱性レコード内に検証済みコード片は見つかりませんでした",
            "脆弱性レコード内に検証済み修正コード片は見つかりませんでした",
            "취약점 기록에서 검증 가능한 코드 조각을 찾지 못했습니다",
            "취약점 기록에서 검증 가능한 수정 코드 조각을 찾지 못했습니다",
        ].contains(normalized)
    }
}

private struct AssistantLoadingBubble: View {
    @EnvironmentObject private var model: AppModel
    let startedAt: Date

    var body: some View {
        HStack(alignment: .top, spacing: 12) {
            AssistantAvatar()
            TimelineView(.periodic(from: .now, by: 1)) { context in
                HStack(spacing: 10) {
                    ProgressView().controlSize(.small)
                    Text(statusText(at: context.date))
                        .font(.callout)
                        .foregroundStyle(AppPalette.textMuted)
                }
            }
            .padding(.horizontal, 18)
            .frame(height: 54)
            .background(AppPalette.card)
            .clipShape(RoundedRectangle(cornerRadius: 14, style: .continuous))
            Spacer()
        }
    }

    private func statusText(at date: Date) -> String {
        let seconds = max(0, Int(date.timeIntervalSince(startedAt)))
        return seconds < 8 ? model.uiText("正在分析 · %d 秒", seconds) : model.uiText("模型处理中 · %d 秒", seconds)
    }
}

private struct AssistantErrorBubble: View {
    let message: String
    let timestamp: Date

    var body: some View {
        HStack(alignment: .top, spacing: 12) {
            AssistantAvatar()
            VStack(alignment: .leading, spacing: 8) {
                Label(message, systemImage: "exclamationmark.triangle.fill")
                    .font(.callout)
                    .foregroundStyle(.red)
                    .padding(16)
                    .background(Color.red.opacity(0.06))
                    .clipShape(RoundedRectangle(cornerRadius: 12))
                Text(timestamp.chatTime)
                    .font(.caption2)
                    .foregroundStyle(AppPalette.textMuted)
            }
            Spacer()
        }
    }
}

private struct AssistantAvatar: View {
    var body: some View {
        Image(systemName: "lock.shield.fill")
            .font(.system(size: 15, weight: .semibold))
            .foregroundStyle(.white)
            .frame(width: 34, height: 34)
            .background(AppPalette.primary)
            .clipShape(Circle())
    }
}

private struct VulnerabilityReportField: View {
    let title: String
    let value: String
    let icon: String
    let tone: Color

    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: icon)
                .font(.caption.weight(.semibold))
                .foregroundStyle(tone)
                .frame(width: 22, height: 22)
                .background(tone.opacity(0.1))
                .clipShape(RoundedRectangle(cornerRadius: 6, style: .continuous))
            VStack(alignment: .leading, spacing: 4) {
                Text(title)
                    .font(.caption.weight(.semibold))
                    .foregroundStyle(AppPalette.textMuted)
                Text(value)
                    .font(.callout)
                    .foregroundStyle(AppPalette.text)
                    .lineSpacing(3)
                    .textSelection(.enabled)
            }
            Spacer(minLength: 0)
        }
        .padding(11)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(tone.opacity(0.055))
        .clipShape(RoundedRectangle(cornerRadius: 8, style: .continuous))
        .overlay {
            RoundedRectangle(cornerRadius: 8, style: .continuous)
                .stroke(tone.opacity(0.18))
        }
    }
}

private struct VulnerabilityDescriptionField: View {
    @EnvironmentObject private var model: AppModel
    let value: String
    let score: String?
    let severity: String?

    @State private var isExpanded = true

    var body: some View {
        VStack(alignment: .leading, spacing: 9) {
            Button {
                withAnimation(.easeInOut(duration: 0.16)) {
                    isExpanded.toggle()
                }
            } label: {
                HStack(spacing: 8) {
                    Image(systemName: isExpanded ? "chevron.down" : "chevron.right")
                        .font(.caption.weight(.bold))
                        .foregroundStyle(AppPalette.textMuted)
                        .frame(width: 12)
                    Text(model.uiText("漏洞描述"))
                        .font(.caption.weight(.semibold))
                        .foregroundStyle(AppPalette.textMuted)
                    Spacer()
                    if let score, !score.isEmpty {
                        Text("CVSS \(score) · \(severityText)")
                            .font(.caption.weight(.semibold))
                            .foregroundStyle(StatusTone.severity(severity ?? "").color)
                    }
                }
            }
            .buttonStyle(.plain)

            Text(value)
                .font(.callout)
                .foregroundStyle(AppPalette.text)
                .lineSpacing(4)
                .lineLimit(isExpanded ? nil : 3)
                .fixedSize(horizontal: false, vertical: true)
                .textSelection(.enabled)
                .frame(maxWidth: .infinity, alignment: .leading)
        }
        .padding(11)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(AppPalette.primary.opacity(0.045))
        .clipShape(RoundedRectangle(cornerRadius: 8, style: .continuous))
        .overlay {
            RoundedRectangle(cornerRadius: 8, style: .continuous)
                .stroke(AppPalette.primary.opacity(0.14))
        }
    }

    private var severityText: String {
        guard let severity, !severity.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            return model.uiText("风险待核验")
        }
        return severityLabel(severity, language: model.appLanguage)
    }
}

private struct VulnerabilityCodeSnippet: View {
    let title: String
    let code: String
    let tone: Color

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Label(title, systemImage: "chevron.left.forwardslash.chevron.right")
                .font(.caption.weight(.semibold))
                .foregroundStyle(tone)
            Text(code)
                .font(.system(.caption, design: .monospaced))
                .foregroundStyle(AppPalette.text)
                .lineSpacing(3)
                .textSelection(.enabled)
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(12)
                .background(AppPalette.cardMuted)
                .clipShape(RoundedRectangle(cornerRadius: 8, style: .continuous))
                .overlay {
                    RoundedRectangle(cornerRadius: 8, style: .continuous)
                        .stroke(tone.opacity(0.22))
                }
        }
    }
}

private struct VulnerabilityReferenceLinks: View {
    @EnvironmentObject private var model: AppModel
    let value: String

    private var links: [String] {
        let separators = CharacterSet(charactersIn: "\n,，；; ")
        return value
            .components(separatedBy: separators)
            .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
            .filter { $0.hasPrefix("http://") || $0.hasPrefix("https://") }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Label(model.uiText("参考链接"), systemImage: "link")
                .font(.caption.weight(.semibold))
                .foregroundStyle(AppPalette.textMuted)

            if links.isEmpty {
                Text(value)
                    .font(.callout)
                    .foregroundStyle(AppPalette.textMuted)
            } else {
                VStack(alignment: .leading, spacing: 7) {
                    ForEach(links, id: \.self) { item in
                        if let url = URL(string: item) {
                            Link(destination: url) {
                                HStack(alignment: .firstTextBaseline, spacing: 7) {
                                    Image(systemName: "arrow.up.right.square")
                                        .font(.caption)
                                    Text(item)
                                        .font(.caption)
                                        .lineLimit(2)
                                }
                                .foregroundStyle(AppPalette.primary)
                                .frame(maxWidth: .infinity, alignment: .leading)
                            }
                        }
                    }
                }
            }
        }
        .padding(11)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(AppPalette.primary.opacity(0.055))
        .clipShape(RoundedRectangle(cornerRadius: 8, style: .continuous))
        .overlay {
            RoundedRectangle(cornerRadius: 8, style: .continuous)
                .stroke(AppPalette.primary.opacity(0.18))
        }
    }
}

private struct ImpactComponentRow: View {
    @EnvironmentObject private var model: AppModel
    let node: KnowledgeNode
    let critical: Bool

    private var tone: Color { critical ? .red : .orange }

    var body: some View {
        HStack(spacing: 10) {
            Image(systemName: "exclamationmark.circle")
                .foregroundStyle(tone)
            Text(node.label)
                .font(.callout.weight(.semibold))
                .foregroundStyle(tone)
                .lineLimit(1)
            Spacer(minLength: 12)
            Text(affectedLabel)
                .font(.caption)
                .foregroundStyle(AppPalette.textMuted)
                .lineLimit(1)
        }
        .padding(.horizontal, 12)
        .frame(minHeight: 40)
        .background(tone.opacity(0.055))
        .clipShape(RoundedRectangle(cornerRadius: 7, style: .continuous))
        .overlay {
            RoundedRectangle(cornerRadius: 7, style: .continuous)
                .stroke(tone.opacity(0.24))
        }
    }

    private var affectedLabel: String {
        let value = node.metadata["affected"]?.text ?? ""
        return value.isEmpty ? model.uiText("受影响版本待核验") : model.uiText("影响 %@", value)
    }
}

private struct MessageActions: View {
    @EnvironmentObject private var model: AppModel
    let text: String
    @State private var feedback: Feedback?
    @State private var copied = false

    var body: some View {
        HStack(spacing: 14) {
            Button {
                feedback = feedback == .helpful ? nil : .helpful
            } label: {
                Image(systemName: feedback == .helpful ? "hand.thumbsup.fill" : "hand.thumbsup")
            }
            .help(model.uiText("有帮助"))

            Button {
                feedback = feedback == .unhelpful ? nil : .unhelpful
            } label: {
                Image(systemName: feedback == .unhelpful ? "hand.thumbsdown.fill" : "hand.thumbsdown")
            }
            .help(model.uiText("需改进"))

            Button {
                NSPasteboard.general.clearContents()
                NSPasteboard.general.setString(text, forType: .string)
                copied = true
            } label: {
                Image(systemName: copied ? "checkmark" : "doc.on.doc")
            }
            .help(copied ? model.uiText("已复制") : model.uiText("复制"))

            ShareLink(item: text) {
                Image(systemName: "arrowshape.turn.up.right")
            }
            .help(model.uiText("分享"))
        }
        .buttonStyle(.plain)
        .foregroundStyle(AppPalette.textMuted)
        .font(.caption)
    }

    private enum Feedback { case helpful, unhelpful }
}

private struct RichAnswerText: View {
    let text: String

    var body: some View {
        Text(text)
            .font(.callout)
            .lineSpacing(4)
            .fixedSize(horizontal: false, vertical: true)
            .textSelection(.enabled)
    }
}

private extension Date {
    var chatTime: String {
        formatted(date: .omitted, time: .shortened)
    }
}
