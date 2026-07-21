import Foundation

struct APIEnvelope<Value: Decodable>: Decodable {
    let status: String
    let message: String
    let data: Value
}

struct ConfigSnapshot: Decodable {
    let collectors: [String: CollectorConfig]
    let records: [VulnerabilityRecord]
    let stats: VulnerabilityStats
    let runtime: RuntimeStatus?
    let dashboard: DashboardSnapshot?
}

struct CollectorConfig: Codable, Identifiable, Equatable {
    let id: String
    let name: String
    var enabled: Bool
    var apiUrl: String
    var apiKey: String?
    var token: String?
    var collectionName: String
    var severityFilter: [String]
    var ecosystem: String?
    var maxResults: Int
    var syncIntervalMinutes: Int
    var lastTest: OperationSummary?
    var lastCollect: OperationSummary?
}

struct OperationSummary: Codable, Equatable {
    let status: String?
    let message: String?
    let inserted: Int?
    let fetched: Int?
    let checkedAt: String?
}

struct VulnerabilityRecord: Codable, Identifiable, Equatable {
    let id: String
    let title: String
    let severity: String
    let cvssScore: Double?
    let source: String?
    let summary: String?
    let affectedVersions: [String]?
    let fixedVersions: [String]?
    let references: [String]?
    let collection: String?
    let publishedAt: String?
    let updatedAt: String
}

struct VulnerabilityStats: Codable, Equatable {
    let total: Int
    let byCollection: [String: Int]
    let bySeverity: [String: Int]
}

struct RuntimeStatus: Codable, Equatable {
    let llm: LLMRuntime
    let memory: MemoryRuntime
}

struct TrialStatusSnapshot: Codable, Equatable {
    let enabled: Bool
    let usable: Bool
    let state: String
    let durationHours: Int
    let startedAt: String?
    let expiresAt: String?
    let lastSeenAt: String?
    let secondsRemaining: Int?
    let message: String

    func isUsable(at date: Date) -> Bool {
        guard enabled else { return true }
        guard usable else { return false }
        guard let expirationDate else { return usable }
        return date < expirationDate
    }

    func remainingSeconds(at date: Date) -> Int {
        guard let expirationDate else { return max(0, secondsRemaining ?? 0) }
        return max(0, Int(expirationDate.timeIntervalSince(date).rounded(.up)))
    }

    var startedDate: Date? { Self.parseDate(startedAt) }
    var expirationDate: Date? { Self.parseDate(expiresAt) }

    private static func parseDate(_ value: String?) -> Date? {
        guard let value else { return nil }
        return ISO8601DateFormatter().date(from: value)
    }
}

struct LLMRuntime: Codable, Equatable {
    let configured: Bool
    let provider: String?
    let model: String?
    let endpoint: String?
    let message: String?
}

struct MemoryRuntime: Codable, Equatable {
    let backend: String
    let historyCount: Int
    let configured: Bool?
    let message: String?
}

struct LLMConfigSnapshot: Codable, Equatable {
    let provider: String
    let model: String
    let endpoint: String?
    let enabled: Bool
    let configured: Bool
    let hasApiKey: Bool
    let apiKeyMasked: String?
    let message: String?
    let updatedAt: String?
}

struct LLMConfigPayload: Encodable {
    let provider: String
    let model: String
    let endpoint: String?
    let apiKey: String?
    let enabled: Bool
    let maxTokens: Int
    let temperature: Double
    let topP: Double
    let timeoutMs: Int
    let reasoningEffort: String?
    let disableResponseStorage: Bool?

    init(
        provider: String,
        model: String,
        endpoint: String?,
        apiKey: String?,
        enabled: Bool,
        maxTokens: Int,
        temperature: Double,
        topP: Double,
        timeoutMs: Int,
        reasoningEffort: String? = nil,
        disableResponseStorage: Bool? = nil
    ) {
        self.provider = provider
        self.model = model
        self.endpoint = endpoint
        self.apiKey = apiKey
        self.enabled = enabled
        self.maxTokens = maxTokens
        self.temperature = temperature
        self.topP = topP
        self.timeoutMs = timeoutMs
        self.reasoningEffort = reasoningEffort
        self.disableResponseStorage = disableResponseStorage
    }
}

struct LLMModelsPayload: Encodable {
    let provider: String
    let endpoint: String?
    let apiKey: String?
    let timeoutMs: Int
}

struct LLMModelCatalog: Decodable, Equatable {
    let provider: String
    let source: String
    let models: [LLMRemoteModel]
    let message: String?
}

struct LLMRemoteModel: Decodable, Identifiable, Equatable {
    let id: String
    let name: String?
    let description: String?
}

struct LLMTestResult: Decodable, Equatable {
    let status: String
    let message: String
    let latencyMs: Int?
    let provider: String
    let model: String
    let configured: Bool
}

struct SettingsSnapshot: Decodable, Equatable {
    let profile: UserProfileSettingsSnapshot
    let preferences: AppPreferenceSettingsSnapshot
    let about: AboutSettingsSnapshot
    let legal: [String: LegalDocumentSnapshot]?
}

struct UserProfileSettingsSnapshot: Codable, Equatable {
    let displayName: String
    let email: String
    let phone: String
    let department: String
    let role: String
    let employeeId: String
    let bio: String
    let avatarFileName: String
    let avatarContentType: String
    let avatarUpdatedAt: String
    let updatedAt: String
    let avatarAvailable: Bool
}

struct UserProfileSettingsPayload: Encodable {
    let displayName: String
    let email: String
    let phone: String
    let department: String
    let role: String
    let employeeId: String
    let bio: String
}

struct AvatarUploadPayload: Encodable {
    let fileName: String
    let contentBase64: String
    let contentType: String?
}

struct AppPreferenceSettingsSnapshot: Codable, Equatable {
    let language: String
    let darkMode: Bool
    let fontSize: String
    let launchAtLogin: Bool
    let autoCheckUpdates: Bool
    let updatedAt: String
}

struct AppPreferenceSettingsPayload: Encodable {
    let language: String
    let darkMode: Bool
    let fontSize: String
    let launchAtLogin: Bool
    let autoCheckUpdates: Bool
}

struct AboutSettingsSnapshot: Decodable, Equatable {
    let name: String
    let subtitle: String
    let version: String
    let releaseChannel: String?
    let versionLabel: String?
    let latest: Bool
    let lastCheckedAt: String
    let copyright: String
    let features: [String]
}

struct LegalDocumentSnapshot: Codable, Equatable, Identifiable {
    let id: String
    let title: String
    let heading: String
    let updatedAt: String
    let effectiveAt: String
    let intro: String
    let sections: [LegalDocumentSectionSnapshot]
    let revisionUpdatedAt: String?
}

struct LegalDocumentSectionSnapshot: Codable, Equatable {
    let heading: String
    let paragraphs: [String]
}

struct AskResult: Decodable, Equatable {
    let mode: String
    let summary: String
    let fields: [String: String]
    let vulnerabilityCard: [String: String]?
    let knowledgeGraph: KnowledgeGraphPayload?
    let chartData: DependencyChartData?
    let report: AnalysisReportSummary?
    let confidence: Double
    let trace: [TraceItem]
    let generatedAt: String

    private enum CodingKeys: String, CodingKey {
        case mode
        case summary
        case fields
        case vulnerabilityCard
        case knowledgeGraph
        case chartData
        case report
        case confidence
        case trace
        case generatedAt
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        mode = try container.decode(String.self, forKey: .mode)
        summary = try container.decode(String.self, forKey: .summary)
        fields = try container.decodeIfPresent([String: JSONValue].self, forKey: .fields)?
            .mapValues(\.text) ?? [:]
        vulnerabilityCard = try container.decodeIfPresent([String: JSONValue].self, forKey: .vulnerabilityCard)?
            .mapValues(\.text)
        knowledgeGraph = try container.decodeIfPresent(KnowledgeGraphPayload.self, forKey: .knowledgeGraph)
        chartData = try container.decodeIfPresent(DependencyChartData.self, forKey: .chartData)
        report = try container.decodeIfPresent(AnalysisReportSummary.self, forKey: .report)
        confidence = try container.decode(Double.self, forKey: .confidence)
        trace = try container.decode([TraceItem].self, forKey: .trace)
        generatedAt = try container.decode(String.self, forKey: .generatedAt)
    }
}

struct DependencyChartData: Codable, Equatable {
    let schemaVersion: Int?
    let sankey: SankeyChartData?
    let severityRing: [ChartMetric]
    let riskBars: [ChartMetric]
    let dag: DAGChartData?

    private enum CodingKeys: String, CodingKey {
        case schemaVersion
        case sankey
        case severityRing
        case riskBars
        case dag
    }

    init(
        schemaVersion: Int? = nil,
        sankey: SankeyChartData? = nil,
        severityRing: [ChartMetric] = [],
        riskBars: [ChartMetric] = [],
        dag: DAGChartData? = nil
    ) {
        self.schemaVersion = schemaVersion
        self.sankey = sankey
        self.severityRing = severityRing
        self.riskBars = riskBars
        self.dag = dag
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        schemaVersion = try container.decodeIfPresent(Int.self, forKey: .schemaVersion)
        sankey = try container.decodeIfPresent(SankeyChartData.self, forKey: .sankey)
        severityRing = try container.decodeIfPresent([ChartMetric].self, forKey: .severityRing) ?? []
        riskBars = try container.decodeIfPresent([ChartMetric].self, forKey: .riskBars) ?? []
        dag = try container.decodeIfPresent(DAGChartData.self, forKey: .dag)
    }

    var hasContent: Bool {
        !(sankey?.nodes.isEmpty ?? true)
            || !severityRing.isEmpty
            || !riskBars.isEmpty
            || !(dag?.nodes.isEmpty ?? true)
    }
}

struct SankeyChartData: Codable, Equatable {
    let nodes: [ChartNode]
    let links: [ChartLink]
}

struct DAGChartData: Codable, Equatable {
    let nodes: [ChartNode]
    let edges: [ChartLink]
}

struct ChartNode: Codable, Equatable, Identifiable {
    let id: String
    let label: String
    let type: String
    let severity: String?
    let column: Int?
    let version: String?
    let ecosystem: String?
}

struct ChartLink: Codable, Equatable, Identifiable {
    let from: String
    let to: String
    let type: String?
    let value: Int
    let severity: String?

    var id: String { "\(from)|\(type ?? "edge")|\(to)" }
}

struct ChartMetric: Codable, Equatable, Identifiable {
    let id: String
    let label: String?
    let key: String?
    let value: Int

    private enum CodingKeys: String, CodingKey {
        case id
        case label
        case key
        case value
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        key = try container.decodeIfPresent(String.self, forKey: .key)
        label = try container.decodeIfPresent(String.self, forKey: .label)
        value = try container.decodeIfPresent(Int.self, forKey: .value) ?? 0
        id = try container.decodeIfPresent(String.self, forKey: .id) ?? key ?? label ?? UUID().uuidString
    }
}

struct AnalysisReportSummary: Decodable, Equatable, Identifiable {
    let id: String
    let title: String
    let fileName: String
    let availableFormats: [String]?
    let createdAt: String
    let mode: String
    let vulnerabilityCount: Int
    let findingCount: Int
}

struct AnalysisReportDetail: Decodable, Equatable, Identifiable {
    let id: String
    let title: String
    let fileName: String
    let availableFormats: [String]?
    let createdAt: String
    let mode: String
    let vulnerabilityCount: Int
    let findingCount: Int
    let content: String
}

enum ReportDownloadFormat: String, CaseIterable, Identifiable {
    case markdown = "md"
    case html
    case pdf

    var id: String { rawValue }

    var label: String {
        switch self {
        case .markdown: "Markdown"
        case .html: "HTML"
        case .pdf: "PDF"
        }
    }

    var fileExtension: String {
        switch self {
        case .markdown: "md"
        case .html: "html"
        case .pdf: "pdf"
        }
    }

    var acceptHeader: String {
        switch self {
        case .markdown: "text/markdown"
        case .html: "text/html"
        case .pdf: "application/pdf"
        }
    }
}

struct ReportDeletePayload: Encodable {
    let reportIds: [String]
}

struct ReportDeleteResult: Decodable, Equatable {
    let requested: Int
    let deleted: Int
    let deletedIds: [String]
    let missingIds: [String]
}

struct ConversationTurn: Identifiable, Equatable {
    let id: UUID
    let question: String
    let attachmentNames: [String]
    let askedAt: Date
    var answer: AskResult?
    var answeredAt: Date?
    var errorMessage: String?

    var attachmentName: String? { attachmentNames.first }

    init(question: String, attachmentName: String? = nil, attachmentNames: [String]? = nil) {
        id = UUID()
        self.question = question
        if let attachmentNames {
            self.attachmentNames = attachmentNames
        } else if let attachmentName {
            self.attachmentNames = [attachmentName]
        } else {
            self.attachmentNames = []
        }
        askedAt = Date()
    }
}

struct TraceItem: Codable, Equatable, Identifiable {
    let node: String
    let status: String
    let message: String
    let time: String

    var id: String { "\(node)|\(time)|\(message)" }
}

struct GraphSpec: Decodable, Equatable {
    let name: String
    let nodes: [WorkflowNode]
    let edges: [WorkflowEdge]
}

struct WorkflowNode: Decodable, Equatable, Identifiable {
    let id: String
    let label: String
}

struct WorkflowEdge: Decodable, Equatable, Identifiable {
    let source: String
    let target: String
    let label: String

    var id: String { "\(source)|\(target)|\(label)" }
}

struct CollectionResult: Decodable, Equatable {
    let status: String
    let message: String
    let inserted: Int
    let fetched: Int
    let records: [VulnerabilityRecord]
    let years: [Int]
    let errors: [String]
    let trace: [TraceItem]
}

struct SaveCollectorResult: Decodable {
    let collector: CollectorConfig
    let message: String
}

struct CollectorUpdate: Encodable {
    let enabled: Bool
    let apiUrl: String
    let apiKey: String?
    let token: String?
    let collectionName: String
    let severityFilter: [String]
    let ecosystem: String?
    let maxResults: Int
    let syncIntervalMinutes: Int
}

struct AskPayload: Encodable {
    let question: String
    let topK: Int
    let userId: String
    let sessionId: String
    let responseLanguage: String
    let attachments: [AskAttachmentPayload]
}

struct AskAttachmentPayload: Encodable, Equatable {
    let fileName: String
    let content: String
    let mimeType: String?
}

struct IntelligenceQueryPayload: Encodable {
    let query: String
    let limit: Int
    let responseLanguage: String?
    let sources: [String]?
}

struct IntelligenceQueryResult: Decodable, Equatable {
    let status: String
    let query: String
    let records: [IntelligenceRecord]
    let graph: KnowledgeGraphPayload
    let sourceStatus: [IntelligenceSource]
    let trace: [TraceItem]
    let persistence: String
    let persisted: PersistenceSummary
    let generatedAt: String
}

struct PersistenceSummary: Decodable, Equatable {
    let inserted: Int
    let updated: Int
}

struct IntelligenceRecord: Decodable, Equatable, Identifiable {
    let id: String
    let title: String
    let severity: String
    let cvssScore: Double?
    let summary: String?
    let affectedVersions: [String]?
    let fixedVersions: [String]?
    let aliases: [String]?
    let cwes: [String]?
    let components: [AffectedComponent]?
    let publishedAt: String?
    let updatedAt: String?
}

struct AffectedComponent: Decodable, Equatable, Identifiable {
    let name: String
    let ecosystem: String
    let affected: [String]
    let fixed: [String]

    var id: String { "\(ecosystem):\(name)" }
}

struct KnowledgeGraphPayload: Decodable, Equatable {
    let query: String?
    let nodes: [KnowledgeNode]
    let edges: [KnowledgeEdge]
    let nodeCount: Int
    let edgeCount: Int

    private enum CodingKeys: String, CodingKey {
        case query
        case nodes
        case edges
        case nodeCount
        case edgeCount
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        query = try container.decodeIfPresent(String.self, forKey: .query)
        nodes = try container.decodeIfPresent([KnowledgeNode].self, forKey: .nodes) ?? []
        edges = try container.decodeIfPresent([KnowledgeEdge].self, forKey: .edges) ?? []
        nodeCount = try container.decodeIfPresent(Int.self, forKey: .nodeCount) ?? nodes.count
        edgeCount = try container.decodeIfPresent(Int.self, forKey: .edgeCount) ?? edges.count
    }
}

struct KnowledgeNode: Decodable, Equatable, Identifiable {
    let id: String
    let label: String
    let type: String
    let metadata: [String: JSONValue]
}

struct KnowledgeEdge: Decodable, Equatable, Identifiable {
    let id: String
    let source: String
    let target: String
    let type: String
    let label: String
}

struct DashboardSnapshot: Decodable, Equatable {
    let vulnerabilityCount: Int
    let highRiskCount: Int
    let queryCount: Int
    let graphNodeCount: Int
    let severity: [String: Int]
    let recentRecords: [IntelligenceRecord]
    let sources: [IntelligenceSource]
    let persistence: String
    let generatedAt: String
    let scope: String?
    let rangeStart: String?
    let rangeEnd: String?
    let catalogStatus: String?
    let catalogProgress: Int?
    let catalogCount: Int?
}

struct DashboardRefreshPayload: Encodable {
    let startDate: String?
    let endDate: String?
}

struct DashboardDateRange: Equatable {
    let start: Date
    let end: Date
}

struct IntelligenceSource: Decodable, Equatable, Identifiable {
    let id: String
    let name: String?
    let kind: String?
    let enabled: Bool?
    let status: String
    let count: Int?
    let lastCount: Int?
    let message: String?
}

struct InformationSnapshot: Decodable, Equatable {
    let items: [InformationItem]
    let total: Int
    let availableTotal: Int
    let categories: [InformationCategory]
    let popularTags: [InformationTag]
    let briefs: [InformationItem]
    let sources: [InformationSource]
    let updatedAt: String
    let lastRefresh: String
    let stale: Bool
    let partial: Bool
    let message: String
}

struct InformationItem: Decodable, Equatable, Identifiable {
    let id: String
    let sourceId: String
    let sourceName: String
    let sourceKind: String
    let title: String
    let summary: String
    let url: String
    let imageUrl: String
    let sourceImageUrl: String?
    let publishedAt: String
    let author: String
    let category: String
    let tags: [String]
    let breaking: Bool
}

struct InformationCategory: Decodable, Equatable, Identifiable {
    let id: String
    let label: String
    let count: Int
}

struct InformationTag: Decodable, Equatable, Identifiable {
    let name: String
    let count: Int

    var id: String { name }
}

struct InformationSource: Decodable, Equatable, Identifiable {
    let id: String
    let name: String
    let kind: String
    let website: String
    let region: String
    let enabled: Bool
    let status: String
    let itemCount: Int
    let lastUpdated: String
    let message: String
}

struct InformationSourceUpdate: Encodable {
    let enabled: Bool
}

enum JSONValue: Decodable, Equatable {
    case string(String)
    case number(Double)
    case bool(Bool)
    case array([JSONValue])
    case object([String: JSONValue])
    case null

    init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        if container.decodeNil() { self = .null }
        else if let value = try? container.decode(Bool.self) { self = .bool(value) }
        else if let value = try? container.decode(Double.self) { self = .number(value) }
        else if let value = try? container.decode(String.self) { self = .string(value) }
        else if let value = try? container.decode([JSONValue].self) { self = .array(value) }
        else { self = .object(try container.decode([String: JSONValue].self)) }
    }

    var text: String {
        switch self {
        case let .string(value): value
        case let .number(value): String(format: "%g", value)
        case let .bool(value): value ? "true" : "false"
        case let .array(values): values.map(\.text).joined(separator: ", ")
        case let .object(value): value.map { "\($0.key): \($0.value.text)" }.joined(separator: ", ")
        case .null: ""
        }
    }
}

extension JSONDecoder {
    static var secFlow: JSONDecoder {
        let decoder = JSONDecoder()
        decoder.keyDecodingStrategy = .convertFromSnakeCase
        return decoder
    }
}

extension JSONEncoder {
    static var secFlow: JSONEncoder {
        let encoder = JSONEncoder()
        encoder.keyEncodingStrategy = .convertToSnakeCase
        return encoder
    }
}
