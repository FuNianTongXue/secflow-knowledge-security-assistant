import Foundation

enum APIClientError: LocalizedError {
    case invalidServerURL
    case invalidResponse
    case decoding(String)
    case server(status: Int, message: String)

    var errorDescription: String? {
        switch self {
        case .invalidServerURL:
            return "服务地址无效，请在设置中填写完整的 http 或 https 地址。"
        case .invalidResponse:
            return "服务返回了无法识别的响应。"
        case let .decoding(detail):
            return "本地数据解析失败：\(detail)"
        case let .server(status, message):
            return "HTTP \(status)：\(message)"
        }
    }
}

struct APIClient {
    let baseURL: URL

    init(serverURL: String) throws {
        guard let url = URL(string: serverURL.trimmingCharacters(in: .whitespacesAndNewlines)),
              let scheme = url.scheme?.lowercased(),
              ["http", "https"].contains(scheme),
              url.host != nil
        else {
            throw APIClientError.invalidServerURL
        }
        baseURL = url
    }

    func loadConfig() async throws -> ConfigSnapshot {
        try await request("api/config")
    }

    func loadRuntime() async throws -> RuntimeStatus {
        try await request("api/runtime")
    }

    func loadTrialStatus() async throws -> TrialStatusSnapshot {
        try await request("api/trial/status")
    }

    func loadLLMConfig() async throws -> LLMConfigSnapshot {
        try await request("api/llm/config")
    }

    func saveLLMConfig(_ payload: LLMConfigPayload) async throws -> LLMConfigSnapshot {
        try await request("api/llm/config", method: "PATCH", body: payload)
    }

    func testLLMConfig(_ payload: LLMConfigPayload) async throws -> LLMTestResult {
        try await request("api/llm/test", method: "POST", body: payload)
    }

    func loadLLMModels(_ payload: LLMModelsPayload) async throws -> LLMModelCatalog {
        try await request("api/llm/models", method: "POST", body: payload)
    }

    func loadSettings() async throws -> SettingsSnapshot {
        try await request("api/settings")
    }

    func loadProfileSettings() async throws -> UserProfileSettingsSnapshot {
        try await request("api/settings/profile")
    }

    func saveProfileSettings(_ payload: UserProfileSettingsPayload) async throws -> UserProfileSettingsSnapshot {
        try await request("api/settings/profile", method: "PATCH", body: payload)
    }

    func uploadProfileAvatar(_ payload: AvatarUploadPayload) async throws -> UserProfileSettingsSnapshot {
        try await request("api/settings/profile/avatar", method: "POST", body: payload, timeoutInterval: 90)
    }

    func deleteProfileAvatar() async throws -> UserProfileSettingsSnapshot {
        try await request("api/settings/profile/avatar", method: "DELETE")
    }

    func downloadProfileAvatar() async throws -> Data {
        let url = baseURL.appending(path: "api/settings/profile/avatar")
        var request = URLRequest(url: url)
        request.httpMethod = "GET"
        request.timeoutInterval = 65
        request.setValue("image/*", forHTTPHeaderField: "Accept")
        let (data, response) = try await URLSession.shared.data(for: request)
        guard let http = response as? HTTPURLResponse else {
            throw APIClientError.invalidResponse
        }
        guard (200..<300).contains(http.statusCode) else {
            let detail = (try? JSONDecoder.secFlow.decode(ErrorPayload.self, from: data).resolvedMessage)
                ?? HTTPURLResponse.localizedString(forStatusCode: http.statusCode)
            throw APIClientError.server(status: http.statusCode, message: detail)
        }
        return data
    }

    func loadPreferenceSettings() async throws -> AppPreferenceSettingsSnapshot {
        try await request("api/settings/preferences")
    }

    func savePreferenceSettings(_ payload: AppPreferenceSettingsPayload) async throws -> AppPreferenceSettingsSnapshot {
        try await request("api/settings/preferences", method: "PATCH", body: payload)
    }

    func loadLegalDocuments() async throws -> [String: LegalDocumentSnapshot] {
        try await request("api/settings/legal")
    }

    func loadLegalDocument(id: String) async throws -> LegalDocumentSnapshot {
        let cleanID = id.addingPercentEncoding(withAllowedCharacters: .urlPathAllowed) ?? id
        return try await request("api/settings/legal/\(cleanID)")
    }

    func loadGraph() async throws -> GraphSpec {
        try await request("api/graph")
    }

    func loadCollectorGraph() async throws -> GraphSpec {
        try await request("api/collector-graph")
    }

    func loadDashboard(startDate: String? = nil, endDate: String? = nil) async throws -> DashboardSnapshot {
        var queryItems: [URLQueryItem] = []
        if let startDate, let endDate {
            queryItems = [
                URLQueryItem(name: "start_date", value: startDate),
                URLQueryItem(name: "end_date", value: endDate),
            ]
        }
        return try await request("api/dashboard", queryItems: queryItems)
    }

    func refreshDashboardBatch(_ payload: DashboardRefreshPayload) async throws -> DashboardSnapshot {
        try await request("api/dashboard/refresh", method: "POST", body: payload)
    }

    func loadIntelligenceSources() async throws -> [IntelligenceSource] {
        try await request("api/intelligence/sources")
    }

    func loadRecentIntelligence() async throws -> [IntelligenceQueryResult] {
        try await request("api/intelligence/recent")
    }

    func queryIntelligence(_ payload: IntelligenceQueryPayload) async throws -> IntelligenceQueryResult {
        try await request("api/intelligence/query", method: "POST", body: payload)
    }

    func loadInformation(refresh: Bool = false) async throws -> InformationSnapshot {
        try await request(
            "api/information",
            queryItems: refresh ? [URLQueryItem(name: "refresh", value: "true")] : []
        )
    }

    func refreshInformation() async throws -> InformationSnapshot {
        try await request("api/information/refresh", method: "POST")
    }

    func updateInformationSource(id: String, enabled: Bool) async throws -> InformationSource {
        let cleanID = id.addingPercentEncoding(withAllowedCharacters: .urlPathAllowed) ?? id
        return try await request(
            "api/information/sources/\(cleanID)",
            method: "PATCH",
            body: InformationSourceUpdate(enabled: enabled)
        )
    }

    func ask(_ payload: AskPayload) async throws -> AskResult {
        let timeout: TimeInterval = if payload.attachments.isEmpty {
            90
        } else if payload.attachments.count > 80 {
            900
        } else {
            420
        }
        return try await request("api/ask", method: "POST", body: payload, timeoutInterval: timeout)
    }

    func loadReports() async throws -> [AnalysisReportSummary] {
        try await request("api/reports")
    }

    func loadReport(id: String) async throws -> AnalysisReportDetail {
        try await request("api/reports/\(id)")
    }

    func downloadReport(id: String, format: ReportDownloadFormat = .markdown) async throws -> Data {
        let cleanID = id.addingPercentEncoding(withAllowedCharacters: .urlPathAllowed) ?? id
        var components = URLComponents(
            url: baseURL.appending(path: "api/reports/\(cleanID)/download"),
            resolvingAgainstBaseURL: false
        )
        components?.queryItems = [URLQueryItem(name: "format", value: format.rawValue)]
        guard let url = components?.url else {
            throw APIClientError.invalidServerURL
        }
        var request = URLRequest(url: url)
        request.httpMethod = "GET"
        request.timeoutInterval = 65
        request.setValue(format.acceptHeader, forHTTPHeaderField: "Accept")
        let (data, response) = try await URLSession.shared.data(for: request)
        guard let http = response as? HTTPURLResponse else {
            throw APIClientError.invalidResponse
        }
        guard (200..<300).contains(http.statusCode) else {
            let detail = (try? JSONDecoder.secFlow.decode(ErrorPayload.self, from: data).resolvedMessage)
                ?? HTTPURLResponse.localizedString(forStatusCode: http.statusCode)
            throw APIClientError.server(status: http.statusCode, message: detail)
        }
        return data
    }

    func deleteReports(ids: [String]) async throws -> ReportDeleteResult {
        try await request("api/reports", method: "DELETE", body: ReportDeletePayload(reportIds: ids))
    }

    func saveCollector(id: String, update: CollectorUpdate) async throws -> SaveCollectorResult {
        try await request("api/config/\(id)", method: "PATCH", body: update)
    }

    func testCollector(id: String) async throws -> OperationSummary {
        try await request("api/config/\(id)/test", method: "POST")
    }

    func collect(id: String) async throws -> CollectionResult {
        try await request("api/collect/\(id)", method: "POST")
    }

    private func request<Value: Decodable>(
        _ path: String,
        method: String = "GET",
        queryItems: [URLQueryItem] = []
    ) async throws -> Value {
        try await request(path, method: method, queryItems: queryItems, bodyData: nil)
    }

    private func request<Value: Decodable, Body: Encodable>(
        _ path: String,
        method: String,
        body: Body,
        timeoutInterval: TimeInterval = 65
    ) async throws -> Value {
        try await request(
            path,
            method: method,
            queryItems: [],
            bodyData: JSONEncoder.secFlow.encode(body),
            timeoutInterval: timeoutInterval
        )
    }

    private func request<Value: Decodable>(
        _ path: String,
        method: String,
        queryItems: [URLQueryItem],
        bodyData: Data?,
        timeoutInterval: TimeInterval = 65
    ) async throws -> Value {
        let cleanPath = path.trimmingCharacters(in: CharacterSet(charactersIn: "/"))
        var components = URLComponents(
            url: baseURL.appending(path: cleanPath),
            resolvingAgainstBaseURL: false
        )
        components?.queryItems = queryItems.isEmpty ? nil : queryItems
        guard let url = components?.url else {
            throw APIClientError.invalidServerURL
        }
        var request = URLRequest(url: url)
        request.httpMethod = method
        request.timeoutInterval = timeoutInterval
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        if let bodyData {
            request.httpBody = bodyData
            request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        }

        let (data, response) = try await URLSession.shared.data(for: request)
        guard let http = response as? HTTPURLResponse else {
            throw APIClientError.invalidResponse
        }
        guard (200..<300).contains(http.statusCode) else {
            let detail = (try? JSONDecoder.secFlow.decode(ErrorPayload.self, from: data).resolvedMessage)
                ?? HTTPURLResponse.localizedString(forStatusCode: http.statusCode)
            throw APIClientError.server(status: http.statusCode, message: detail)
        }
        do {
            return try JSONDecoder.secFlow.decode(APIEnvelope<Value>.self, from: data).data
        } catch {
            throw APIClientError.decoding(String(describing: error))
        }
    }
}

private struct ErrorPayload: Decodable {
    let detail: String?
    let message: String?

    var resolvedMessage: String {
        detail ?? message ?? "服务请求失败。"
    }
}
