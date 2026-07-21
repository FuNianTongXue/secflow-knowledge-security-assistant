import Foundation

@MainActor
final class AppModel: ObservableObject {
    @Published private(set) var serverURL: String
    @Published var config: ConfigSnapshot?
    @Published var runtime: RuntimeStatus?
    @Published var trialStatus: TrialStatusSnapshot?
    @Published var llmConfig: LLMConfigSnapshot?
    @Published var llmModelCatalog: LLMModelCatalog?
    @Published var dashboard: DashboardSnapshot?
    @Published var dashboardRange: DashboardDateRange?
    @Published var intelligenceSources: [IntelligenceSource] = []
    @Published var intelligenceResult: IntelligenceQueryResult?
    @Published var queryLogs: [IntelligenceQueryResult] = []
    @Published var information: InformationSnapshot?
    @Published var settings: SettingsSnapshot?
    @Published var profileSettings: UserProfileSettingsSnapshot?
    @Published var preferenceSettings: AppPreferenceSettingsSnapshot?
    @Published var aboutSettings: AboutSettingsSnapshot?
    @Published var legalDocuments: [String: LegalDocumentSnapshot] = [:]
    @Published var profileAvatarImageData: Data?
    @Published var knowledgeGraph: KnowledgeGraphPayload?
    @Published var assistantGraph: GraphSpec?
    @Published var collectorGraph: GraphSpec?
    @Published var answer: AskResult?
    @Published var conversationTurns: [ConversationTurn] = []
    @Published var reports: [AnalysisReportSummary] = []
    @Published var selectedReport: AnalysisReportDetail?
    @Published var activeTrace: [TraceItem] = []
    @Published var isRefreshing = false
    @Published var isAsking = false
    @Published var busyActions: Set<String> = []
    @Published var errorMessage: String?
    @Published var statusMessage: String?
    @Published var isAuthenticated: Bool
    @Published var authScreen: AuthScreen = .login
    @Published var initialSetupState: InitialSetupState = .loading
    @Published var appLanguage: AppLanguage

    @Published var userID: String
    @Published private(set) var sessionID: String

    private let localBackend = LocalBackendManager.shared

    var dataDirectoryURL: URL { localBackend.dataDirectoryURL }

    init() {
        serverURL = LocalBackendManager.shared.baseURLString
        UserDefaults.standard.removeObject(forKey: "secflow.serverURL")
        userID = UserDefaults.standard.string(forKey: "secflow.userID") ?? "local-user"
        appLanguage = AppLanguage.storedValue()
        isAuthenticated = ProcessInfo.processInfo.environment["SECFLOW_SKIP_AUTH"] == "1"
        if let stored = UserDefaults.standard.string(forKey: "secflow.sessionID") {
            sessionID = stored
        } else {
            let value = UUID().uuidString
            UserDefaults.standard.set(value, forKey: "secflow.sessionID")
            sessionID = value
        }
    }

    func refreshAll() async {
        isRefreshing = true
        errorMessage = nil
        defer { isRefreshing = false }
        do {
            let client = try await connectedClient()
            trialStatus = try await client.loadTrialStatus()
            if let trialStatus, !trialStatus.isUsable(at: Date()) {
                initialSetupState = .failed(trialStatus.message)
                return
            }
            async let configRequest = client.loadConfig()
            async let llmConfigRequest: LLMConfigSnapshot? = try? await client.loadLLMConfig()
            async let graphRequest: GraphSpec? = try? await client.loadGraph()
            async let collectorGraphRequest: GraphSpec? = try? await client.loadCollectorGraph()
            async let dashboardRequest: DashboardSnapshot? = try? await client.loadDashboard()
            async let recentRequest: [IntelligenceQueryResult]? = try? await client.loadRecentIntelligence()
            async let reportsRequest: [AnalysisReportSummary]? = try? await client.loadReports()
            async let settingsRequest: SettingsSnapshot? = try? await client.loadSettings()

            let loadedConfig = try await configRequest
            let loadedLLMConfig = await llmConfigRequest
            config = loadedConfig
            llmConfig = loadedLLMConfig
            updateInitialSetupState()
            assistantGraph = await graphRequest
            collectorGraph = await collectorGraphRequest
            dashboard = (await dashboardRequest) ?? loadedConfig.dashboard

            if let snapshotRuntime = loadedConfig.runtime {
                runtime = snapshotRuntime
            } else {
                runtime = try? await client.loadRuntime()
            }
            intelligenceSources = dashboard?.sources ?? []
            if let recent = await recentRequest {
                queryLogs = recent
                if let latest = recent.first {
                    intelligenceResult = latest
                    knowledgeGraph = latest.graph
                }
            }
            reports = (await reportsRequest) ?? reports
            if let loadedSettings = await settingsRequest {
                applySettingsSnapshot(loadedSettings)
                profileAvatarImageData = loadedSettings.profile.avatarAvailable ? (try? await client.downloadProfileAvatar()) : nil
            }
            statusMessage = uiText("本机数据服务已连接")
        } catch {
            errorMessage = localizedError(error)
            if initialSetupState == .loading {
                initialSetupState = .failed(errorMessage ?? localizedError(error))
            }
        }
    }

    func refreshTrialStatus() async {
        do {
            let client = try await connectedClient()
            trialStatus = try await client.loadTrialStatus()
        } catch {
            if trialStatus == nil {
                errorMessage = localizedError(error)
            }
        }
    }

    func runTrialStatusLoop() async {
        while !Task.isCancelled {
            do {
                try await Task.sleep(nanoseconds: 10_000_000_000)
            } catch {
                return
            }
            await refreshTrialStatus()
        }
    }

    func refreshDashboardSnapshot() async {
        do {
            let client = try await connectedClient()
            let range = dashboardRangeStrings
            async let dashboardRequest = client.loadDashboard(startDate: range.start, endDate: range.end)
            async let recentRequest: [IntelligenceQueryResult]? = try? await client.loadRecentIntelligence()

            dashboard = try await dashboardRequest
            if let recent = await recentRequest {
                queryLogs = recent
                if let latest = recent.first {
                    intelligenceResult = latest
                    knowledgeGraph = latest.graph
                }
            }
        } catch {
            if dashboard == nil {
                errorMessage = localizedError(error)
            }
        }
    }

    func loadLLMConfig() async {
        do {
            let client = try await connectedClient()
            llmConfig = try await client.loadLLMConfig()
            updateInitialSetupState()
            runtime = try? await client.loadRuntime()
        } catch {
            errorMessage = localizedError(error)
        }
    }

    func testLLMConfig(_ payload: LLMConfigPayload) async -> LLMTestResult? {
        busyActions.insert("llm-test")
        errorMessage = nil
        defer { busyActions.remove("llm-test") }
        do {
            let client = try await connectedClient()
            let result = try await client.testLLMConfig(payload)
            statusMessage = localizedMessage(result.message)
            return result
        } catch {
            errorMessage = localizedError(error)
            return nil
        }
    }

    func saveLLMConfig(_ payload: LLMConfigPayload) async {
        busyActions.insert("llm-save")
        errorMessage = nil
        defer { busyActions.remove("llm-save") }
        do {
            let client = try await connectedClient()
            llmConfig = try await client.saveLLMConfig(payload)
            updateInitialSetupState()
            runtime = try? await client.loadRuntime()
            config = try? await client.loadConfig()
            statusMessage = payload.enabled ? uiText("大模型配置已保存并启用") : uiText("大模型连接已断开")
        } catch {
            errorMessage = localizedError(error)
        }
    }

    func loadLLMModels(_ payload: LLMModelsPayload) async {
        busyActions.insert("llm-models")
        errorMessage = nil
        defer { busyActions.remove("llm-models") }
        do {
            let client = try await connectedClient()
            llmModelCatalog = try await client.loadLLMModels(payload)
            statusMessage = localizedMessage(llmModelCatalog?.message)
        } catch {
            errorMessage = localizedError(error)
        }
    }

    func loadSettings() async {
        busyActions.insert("settings-load")
        errorMessage = nil
        defer { busyActions.remove("settings-load") }
        do {
            let client = try await connectedClient()
            let loadedSettings = try await client.loadSettings()
            applySettingsSnapshot(loadedSettings)
            profileAvatarImageData = loadedSettings.profile.avatarAvailable ? (try? await client.downloadProfileAvatar()) : nil
        } catch {
            errorMessage = localizedError(error)
        }
    }

    @discardableResult
    func saveProfileSettings(_ payload: UserProfileSettingsPayload) async -> Bool {
        busyActions.insert("settings-profile-save")
        errorMessage = nil
        defer { busyActions.remove("settings-profile-save") }
        do {
            let client = try await connectedClient()
            profileSettings = try await client.saveProfileSettings(payload)
            settings = rebuildSettingsSnapshot()
            statusMessage = uiText("用户资料已保存")
            return true
        } catch {
            errorMessage = localizedError(error)
            return false
        }
    }

    @discardableResult
    func uploadProfileAvatar(_ payload: AvatarUploadPayload) async -> Bool {
        busyActions.insert("settings-avatar-upload")
        errorMessage = nil
        defer { busyActions.remove("settings-avatar-upload") }
        do {
            let client = try await connectedClient()
            profileSettings = try await client.uploadProfileAvatar(payload)
            profileAvatarImageData = try? await client.downloadProfileAvatar()
            settings = rebuildSettingsSnapshot()
            statusMessage = uiText("头像已上传")
            return true
        } catch {
            errorMessage = localizedError(error)
            return false
        }
    }

    @discardableResult
    func deleteProfileAvatar() async -> Bool {
        busyActions.insert("settings-avatar-delete")
        errorMessage = nil
        defer { busyActions.remove("settings-avatar-delete") }
        do {
            let client = try await connectedClient()
            profileSettings = try await client.deleteProfileAvatar()
            profileAvatarImageData = nil
            settings = rebuildSettingsSnapshot()
            statusMessage = uiText("头像已移除")
            return true
        } catch {
            errorMessage = localizedError(error)
            return false
        }
    }

    @discardableResult
    func savePreferenceSettings(_ payload: AppPreferenceSettingsPayload) async -> Bool {
        busyActions.insert("settings-preferences-save")
        errorMessage = nil
        defer { busyActions.remove("settings-preferences-save") }
        do {
            let client = try await connectedClient()
            preferenceSettings = try await client.savePreferenceSettings(payload)
            if let language = AppLanguage(apiCode: preferenceSettings?.language ?? payload.language) {
                setLanguage(language)
            }
            settings = rebuildSettingsSnapshot()
            statusMessage = uiText("通用设置已保存")
            return true
        } catch {
            errorMessage = localizedError(error)
            return false
        }
    }

    func loadLegalDocuments() async {
        busyActions.insert("settings-legal-load")
        errorMessage = nil
        defer { busyActions.remove("settings-legal-load") }
        do {
            let client = try await connectedClient()
            legalDocuments = try await client.loadLegalDocuments()
            settings = rebuildSettingsSnapshot()
        } catch {
            errorMessage = localizedError(error)
        }
    }

    func loadLegalDocument(id: String) async {
        busyActions.insert("settings-legal-load:\(id)")
        errorMessage = nil
        defer { busyActions.remove("settings-legal-load:\(id)") }
        do {
            let client = try await connectedClient()
            let document = try await client.loadLegalDocument(id: id)
            legalDocuments[document.id] = document
            settings = rebuildSettingsSnapshot()
        } catch {
            errorMessage = localizedError(error)
        }
    }

    func refreshDashboardBatch(startDate: Date? = nil, endDate: Date? = nil) async {
        busyActions.insert("dashboard-batch")
        defer { busyActions.remove("dashboard-batch") }
        do {
            let client = try await connectedClient()
            let requestedRange: DashboardDateRange?
            if let startDate, let endDate {
                requestedRange = DashboardDateRange(
                    start: min(startDate, endDate),
                    end: max(startDate, endDate)
                )
            } else {
                requestedRange = nil
            }
            let strings = dashboardRangeStrings(for: requestedRange)
            if let cachedDashboard = try? await client.loadDashboard(startDate: strings.start, endDate: strings.end) {
                dashboard = cachedDashboard
                dashboardRange = requestedRange
            }
            dashboard = try await client.refreshDashboardBatch(
                DashboardRefreshPayload(startDate: strings.start, endDate: strings.end)
            )
            dashboardRange = requestedRange
            if let recent = try? await client.loadRecentIntelligence() {
                queryLogs = recent
            }
            statusMessage = requestedRange == nil ? uiText("安全总览已更新累计数据") : uiText("安全总览已按时间范围更新")
        } catch {
            errorMessage = localizedError(error)
        }
    }

    func applyDashboardRange(startDate: Date, endDate: Date) async {
        let previousRange = dashboardRange
        dashboardRange = DashboardDateRange(
            start: min(startDate, endDate),
            end: max(startDate, endDate)
        )
        busyActions.insert("dashboard-filter")
        do {
            let client = try await connectedClient()
            let range = dashboardRangeStrings
            dashboard = try await client.loadDashboard(startDate: range.start, endDate: range.end)
            statusMessage = uiText("安全总览已切换到所选发布日期范围")
        } catch {
            dashboardRange = previousRange
            errorMessage = localizedError(error)
        }
        busyActions.remove("dashboard-filter")
    }

    func runDashboardAutoRefreshLoop() async {
        var tick = 0
        while !Task.isCancelled {
            do {
                try await Task.sleep(nanoseconds: 60_000_000_000)
            } catch {
                return
            }
            tick += 1
            if tick % 15 == 0 && dashboardRange == nil {
                await refreshDashboardBatch()
            } else {
                await refreshDashboardSnapshot()
            }
        }
    }

    @discardableResult
    func ask(question: String, topK: Int, attachments: [AskAttachmentPayload] = []) async -> AskResult? {
        let cleanQuestion = question.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !cleanQuestion.isEmpty else { return nil }
        isAsking = true
        errorMessage = nil
        activeTrace = []
        defer { isAsking = false }
        do {
            let client = try await connectedClient()
            let result = try await client.ask(
                AskPayload(
                    question: cleanQuestion,
                    topK: topK,
                    userId: userID,
                    sessionId: sessionID,
                    responseLanguage: appLanguage.apiCode,
                    attachments: attachments
                )
            )
            answer = result
            activeTrace = result.trace
            knowledgeGraph = result.knowledgeGraph
            if let report = result.report {
                reports.removeAll { $0.id == report.id }
                reports.insert(report, at: 0)
            }
            Task { await refreshStateAfterAnswer() }
            return result
        } catch is CancellationError {
            errorMessage = uiText("已停止生成")
        } catch let error as URLError where error.code == .cancelled {
            errorMessage = uiText("已停止生成")
        } catch {
            errorMessage = localizedError(error)
        }
        return nil
    }

    private func refreshStateAfterAnswer() async {
        do {
            let client = try await connectedClient()
            let range = dashboardRangeStrings
            async let runtimeRequest: RuntimeStatus? = try? await client.loadRuntime()
            async let dashboardRequest: DashboardSnapshot? = try? await client.loadDashboard(startDate: range.start, endDate: range.end)
            async let recentRequest: [IntelligenceQueryResult]? = try? await client.loadRecentIntelligence()
            async let reportsRequest: [AnalysisReportSummary]? = try? await client.loadReports()

            runtime = await runtimeRequest
            if let snapshot = await dashboardRequest {
                dashboard = snapshot
            }
            if let recent = await recentRequest {
                queryLogs = recent
            }
            if let loadedReports = await reportsRequest {
                reports = loadedReports
            }
        } catch {
            if dashboard == nil {
                errorMessage = localizedError(error)
            }
        }
    }

    func loadReports() async {
        busyActions.insert("reports")
        errorMessage = nil
        defer { busyActions.remove("reports") }
        do {
            let client = try await connectedClient()
            reports = try await client.loadReports()
            if selectedReport == nil, let first = reports.first {
                selectedReport = try? await client.loadReport(id: first.id)
            }
        } catch {
            errorMessage = localizedError(error)
        }
    }

    func refreshInformation(force: Bool = false) async {
        busyActions.insert("information-refresh")
        errorMessage = nil
        defer { busyActions.remove("information-refresh") }
        do {
            let client = try await connectedClient()
            information = force ? try await client.refreshInformation() : try await client.loadInformation()
            statusMessage = localizedMessage(information?.message)
        } catch {
            errorMessage = localizedError(error)
        }
    }

    func setInformationSource(id: String, enabled: Bool) async {
        let key = "information-source:\(id)"
        busyActions.insert(key)
        errorMessage = nil
        defer { busyActions.remove(key) }
        do {
            let client = try await connectedClient()
            _ = try await client.updateInformationSource(id: id, enabled: enabled)
            information = try await client.loadInformation(refresh: enabled)
            statusMessage = enabled ? uiText("资讯来源已启用") : uiText("资讯来源已暂停")
        } catch {
            errorMessage = localizedError(error)
        }
    }

    func openReport(_ report: AnalysisReportSummary) async {
        busyActions.insert("report:\(report.id)")
        errorMessage = nil
        defer { busyActions.remove("report:\(report.id)") }
        do {
            let client = try await connectedClient()
            selectedReport = try await client.loadReport(id: report.id)
        } catch {
            errorMessage = localizedError(error)
        }
    }

    func downloadReport(_ report: AnalysisReportDetail, to destination: URL, format: ReportDownloadFormat = .markdown) async {
        busyActions.insert("download-report:\(report.id)")
        errorMessage = nil
        defer { busyActions.remove("download-report:\(report.id)") }
        do {
            let client = try await connectedClient()
            let data = try await client.downloadReport(id: report.id, format: format)
            try data.write(to: destination, options: .atomic)
            statusMessage = uiText("报告已保存到 %@", destination.lastPathComponent)
        } catch {
            errorMessage = localizedError(error)
        }
    }

    @discardableResult
    func deleteReports(ids: Set<String>) async -> Int {
        guard !ids.isEmpty else { return 0 }
        busyActions.insert("delete-reports")
        errorMessage = nil
        defer { busyActions.remove("delete-reports") }
        do {
            let client = try await connectedClient()
            let result = try await client.deleteReports(ids: ids.sorted())
            reports = try await client.loadReports()
            if let selectedReport, ids.contains(selectedReport.id) {
                self.selectedReport = nil
            }
            if self.selectedReport == nil, let first = reports.first {
                self.selectedReport = try? await client.loadReport(id: first.id)
            }
            statusMessage = uiText("已删除 %d 份报告", result.deleted)
            return result.deleted
        } catch {
            errorMessage = localizedError(error)
            return 0
        }
    }

    private var dashboardRangeStrings: (start: String?, end: String?) {
        dashboardRangeStrings(for: dashboardRange)
    }

    private func dashboardRangeStrings(for range: DashboardDateRange?) -> (start: String?, end: String?) {
        guard let range else { return (nil, nil) }
        let formatter = DateFormatter()
        formatter.calendar = Calendar(identifier: .gregorian)
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.timeZone = .current
        formatter.dateFormat = "yyyy-MM-dd"
        return (formatter.string(from: range.start), formatter.string(from: range.end))
    }

    func saveCollector(id: String, update: CollectorUpdate) async {
        await performCollectorAction(key: "save:\(id)") { client in
            let result = try await client.saveCollector(id: id, update: update)
            self.statusMessage = self.localizedMessage(result.message)
        }
    }

    func testCollector(id: String) async {
        await performCollectorAction(key: "test:\(id)") { client in
            let result = try await client.testCollector(id: id)
            self.statusMessage = self.localizedMessage(result.message) ?? result.status ?? self.uiText("连接测试已完成")
        }
    }

    func collect(id: String) async {
        await performCollectorAction(key: "collect:\(id)") { client in
            let result = try await client.collect(id: id)
            self.statusMessage = self.localizedMessage(result.message)
            self.activeTrace = result.trace
            let range = self.dashboardRangeStrings
            self.dashboard = try? await client.loadDashboard(startDate: range.start, endDate: range.end)
        }
    }

    func queryIntelligence(query: String, limit: Int = 10) async {
        let cleanQuery = query.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !cleanQuery.isEmpty else { return }
        busyActions.insert("intelligence-query")
        errorMessage = nil
        do {
            let client = try await connectedClient()
            let result = try await client.queryIntelligence(
                IntelligenceQueryPayload(query: cleanQuery, limit: limit, responseLanguage: appLanguage.apiCode, sources: nil)
            )
            intelligenceResult = result
            knowledgeGraph = result.graph
            activeTrace = result.trace
            rememberQueryLog(result)
            let range = dashboardRangeStrings
            dashboard = try? await client.loadDashboard(startDate: range.start, endDate: range.end)
            config = try? await client.loadConfig()
            statusMessage = uiText("API 返回 %d 条漏洞记录", result.records.count)
        } catch {
            errorMessage = localizedError(error)
        }
        busyActions.remove("intelligence-query")
    }

    func enterWorkspace(email: String) {
        let normalized = email.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        userID = normalized.isEmpty ? "local-user" : normalized
        UserDefaults.standard.set(userID, forKey: "secflow.userID")
        initialSetupState = .loading
        isAuthenticated = true
    }

    func signOut() {
        isAuthenticated = false
        authScreen = .login
        initialSetupState = .loading
    }

    func startNewConversation() {
        conversationTurns.removeAll()
        answer = nil
        activeTrace = []
        errorMessage = nil
        let value = UUID().uuidString
        sessionID = value
        UserDefaults.standard.set(value, forKey: "secflow.sessionID")
    }

    func showGraph(_ graph: GraphSpec?) {
        activeTrace = (graph?.nodes ?? []).map {
            TraceItem(node: $0.id, status: "graph-node", message: $0.label, time: graph?.name ?? "")
        }
    }

    func isBusy(_ key: String) -> Bool {
        busyActions.contains(key)
    }

    func text(_ key: L10nKey) -> String {
        localized(key, language: appLanguage)
    }

    func uiText(_ text: String, _ arguments: CVarArg...) -> String {
        localizedUI(text, language: appLanguage, arguments: arguments)
    }

    func localizedMessage(_ message: String?) -> String? {
        guard let message else { return nil }
        let clean = message.trimmingCharacters(in: .whitespacesAndNewlines)
        return clean.isEmpty ? nil : localizedBackendDetail(clean)
    }

    private func localizedError(_ error: Error) -> String {
        if let apiError = error as? APIClientError {
            switch apiError {
            case .invalidServerURL:
                return uiText("服务地址无效，请在设置中填写完整的 http 或 https 地址。")
            case .invalidResponse:
                return uiText("服务返回了无法识别的响应。")
            case let .decoding(detail):
                return uiText("本地数据解析失败：%@", detail)
            case let .server(status, message):
                return "HTTP \(status)：\(localizedBackendDetail(message))"
            }
        }
        if let backendError = error as? LocalBackendError {
            switch backendError {
            case .executableMissing:
                return uiText("应用内本地服务缺失，请重新安装 SecFlow。")
            case let .unavailable(detail):
                return uiText("本地服务启动失败：%@", localizedBackendDetail(detail))
            }
        }
        return localizedBackendDetail(error.localizedDescription)
    }

    private func localizedBackendDetail(_ message: String) -> String {
        let clean = message.trimmingCharacters(in: .whitespacesAndNewlines)
        if clean == "服务地址无效，请在设置中填写完整的 http 或 https 地址。" {
            return uiText("服务地址无效，请在设置中填写完整的 http 或 https 地址。")
        }
        if clean == "服务返回了无法识别的响应。" {
            return uiText("服务返回了无法识别的响应。")
        }
        if clean == "应用内本地服务缺失，请重新安装 SecFlow。" {
            return uiText("应用内本地服务缺失，请重新安装 SecFlow。")
        }
        if clean == "模型配置已启用。" {
            return uiText("模型配置已启用。")
        }
        if clean == "模型配置已保存，尚未启用。" {
            return uiText("模型配置已保存，尚未启用。")
        }
        if clean == "未配置可用模型。" {
            return uiText("未配置可用模型。")
        }
        if clean == "模型接口返回格式不符合 OpenAI Chat Completions。" {
            return uiText("模型接口返回格式不符合 OpenAI Chat Completions。")
        }
        if clean == "当前模型未返回可用结果。" {
            return uiText("当前模型未返回可用结果。")
        }
        if clean == "模型接口调用成功。" {
            return uiText("模型接口调用成功。")
        }
        if clean == "填入 API Key 后，可从厂商模型接口同步真实模型列表。" {
            return uiText("填入 API Key 后，可从厂商模型接口同步真实模型列表。")
        }
        if clean == "API 地址需要包含 http:// 或 https://，当前显示内置推荐模型。" {
            return uiText("API 地址需要包含 http:// 或 https://，当前显示内置推荐模型。")
        }
        if clean == "厂商接口未返回可用模型，已使用内置推荐模型。" {
            return uiText("厂商接口未返回可用模型，已使用内置推荐模型。")
        }
        if clean == "已从厂商模型接口同步模型列表。" {
            return uiText("已从厂商模型接口同步模型列表。")
        }
        if clean == "固定接口可访问。" {
            return uiText("固定接口可访问。")
        }
        if clean == "查询完成" {
            return uiText("查询完成")
        }
        if clean == "查询失败" {
            return uiText("查询失败")
        }
        if clean == "部分完成" {
            return uiText("部分完成")
        }
        if clean == "等待查询" {
            return uiText("等待查询")
        }
        if let value = clean.removingKnownPrefix("模型接口请求失败：", suffix: "") {
            return uiText("模型接口请求失败：%@", value)
        }
        if let value = clean.removingKnownPrefix("厂商模型列表同步失败，已使用内置推荐模型：", suffix: "") {
            return uiText("厂商模型列表同步失败，已使用内置推荐模型：%@", value)
        }
        if let value = clean.removingKnownPrefix("开发服务 ", suffix: " 无法连接。") {
            return uiText("开发服务 %@ 无法连接。", value)
        }
        if let value = clean.removingKnownPrefix("", suffix: " 的接口地址需要包含 http:// 或 https://。") {
            return uiText("%@ 的接口地址需要包含 http:// 或 https://。", value)
        }
        if let value = clean.removingKnownPrefix("进程已退出，请查看 ", suffix: "。") {
            return uiText("进程已退出，请查看 %@。", value)
        }
        if let value = clean.removingKnownPrefix("等待本地服务就绪超时，请查看 ", suffix: "。") {
            return uiText("等待本地服务就绪超时，请查看 %@。", value)
        }
        return clean
    }

    func setLanguage(_ language: AppLanguage) {
        appLanguage = language
        UserDefaults.standard.set(language.rawValue, forKey: "secflow.appLanguage")
        statusMessage = "\(localized(.interfaceLanguage, language: language))：\(language.displayName)"
    }

    private func applySettingsSnapshot(_ snapshot: SettingsSnapshot) {
        settings = snapshot
        profileSettings = snapshot.profile
        preferenceSettings = snapshot.preferences
        aboutSettings = snapshot.about
        legalDocuments = snapshot.legal ?? legalDocuments
        if let language = AppLanguage(apiCode: snapshot.preferences.language), language != appLanguage {
            appLanguage = language
            UserDefaults.standard.set(language.rawValue, forKey: "secflow.appLanguage")
        }
    }

    private func rebuildSettingsSnapshot() -> SettingsSnapshot? {
        guard let profileSettings, let preferenceSettings, let aboutSettings else {
            return settings
        }
        return SettingsSnapshot(
            profile: profileSettings,
            preferences: preferenceSettings,
            about: aboutSettings,
            legal: legalDocuments.isEmpty ? settings?.legal : legalDocuments
        )
    }

    private func rememberQueryLog(_ result: IntelligenceQueryResult) {
        queryLogs.removeAll { $0.generatedAt == result.generatedAt && $0.query == result.query }
        queryLogs.insert(result, at: 0)
        if queryLogs.count > 30 {
            queryLogs = Array(queryLogs.prefix(30))
        }
    }

    private func performCollectorAction(
        key: String,
        operation: (APIClient) async throws -> Void
    ) async {
        busyActions.insert(key)
        errorMessage = nil
        do {
            let client = try await connectedClient()
            try await operation(client)
            config = try await client.loadConfig()
        } catch {
            errorMessage = localizedError(error)
        }
        busyActions.remove(key)
    }

    private func connectedClient() async throws -> APIClient {
        try await localBackend.ensureReady()
        return try APIClient(serverURL: serverURL)
    }

    private func updateInitialSetupState() {
        guard let llmConfig else {
            initialSetupState = .required
            return
        }
        initialSetupState = llmConfig.configured && llmConfig.hasApiKey ? .ready : .required
    }
}

private extension String {
    func removingKnownPrefix(_ prefix: String, suffix: String) -> String? {
        guard hasPrefix(prefix), hasSuffix(suffix), count >= prefix.count + suffix.count else {
            return nil
        }
        return String(dropFirst(prefix.count).dropLast(suffix.count))
    }
}

enum AuthScreen {
    case login
    case register
}

enum InitialSetupState: Equatable {
    case loading
    case required
    case ready
    case failed(String)
}

extension AppLanguage {
    init?(apiCode: String) {
        switch apiCode.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() {
        case "zh-hans", "zh_cn", "zh-cn", "zh", "zhhans":
            self = .zhHans
        case "zh-hant", "zh_tw", "zh-tw", "zh-hk", "zh_hk", "zhtw", "zhhant", "traditional-chinese":
            self = .zhHant
        case "en", "en_us", "en-us", "english":
            self = .en
        case "ko", "ko_kr", "ko-kr", "kr", "korean":
            self = .ko
        case "ja", "ja_jp", "ja-jp", "jp", "japanese":
            self = .ja
        case "es", "es_es", "es-es", "spanish", "español":
            self = .es
        case "fr", "fr_fr", "fr-fr", "french", "français":
            self = .fr
        case "de", "de_de", "de-de", "german", "deutsch":
            self = .de
        case "it", "it_it", "it-it", "italian", "italiano":
            self = .it
        case "ru", "ru_ru", "ru-ru", "russian", "русский":
            self = .ru
        default:
            return nil
        }
    }
}
