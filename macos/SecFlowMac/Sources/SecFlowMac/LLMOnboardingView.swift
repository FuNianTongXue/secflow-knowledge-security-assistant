import SwiftUI

private let onboardingCustomModel = "__secflow_onboarding_custom_model__"

struct LLMOnboardingView: View {
    @EnvironmentObject private var model: AppModel

    @State private var step = 1
    @State private var provider: LLMProvider = .openai
    @State private var selectedModel = LLMProvider.openai.defaultModel
    @State private var customModel = ""
    @State private var endpoint = LLMProvider.openai.defaultEndpoint
    @State private var apiKey = ""
    @State private var isKeyVisible = false
    @State private var testResult: LLMTestResult?
    @State private var didHydrate = false

    private var isTesting: Bool { model.busyActions.contains("llm-test") }
    private var isSaving: Bool { model.busyActions.contains("llm-save") }

    var body: some View {
        HStack(spacing: 0) {
            stepRail
                .frame(width: 286)
            Divider()
            VStack(alignment: .leading, spacing: 0) {
                header
                Divider()
                ScrollView {
                    stepContent
                        .padding(36)
                        .frame(maxWidth: 760, alignment: .leading)
                        .frame(maxWidth: .infinity, alignment: .topLeading)
                }
                navigation
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(AppPalette.page)
        .foregroundStyle(AppPalette.text)
        .task {
            if model.llmConfig == nil {
                await model.loadLLMConfig()
            }
            hydrateFromConfig()
        }
        .onChange(of: model.llmConfig) { _, _ in
            hydrateFromConfig()
        }
    }

    private var stepRail: some View {
        VStack(alignment: .leading, spacing: 28) {
            HStack(spacing: 12) {
                AppBrandLogo(size: 40, shadow: false)
                VStack(alignment: .leading, spacing: 2) {
                    Text(model.text(.appName))
                        .font(.headline)
                        .foregroundStyle(AppPalette.onBrand)
                    Text(model.uiText("首次配置"))
                        .font(.caption)
                        .foregroundStyle(AppPalette.onBrandMuted)
                }
            }

            VStack(alignment: .leading, spacing: 18) {
                ForEach(1...4, id: \.self) { item in
                    onboardingStepRow(item)
                }
            }

            Spacer()
            LanguagePickerMenu(variant: .sidebar)
            Label(model.uiText("密钥仅加密保存在这台 Mac"), systemImage: "lock.fill")
                .font(.caption)
                .foregroundStyle(AppPalette.onBrandMuted)
                .fixedSize(horizontal: false, vertical: true)
        }
        .padding(30)
        .frame(maxHeight: .infinity, alignment: .topLeading)
        .background { SidebarGlassBackground() }
    }

    private func onboardingStepRow(_ item: Int) -> some View {
        let titles = ["选择模型厂商", "选择模型", "填写连接信息", "验证并完成"].map { model.uiText($0) }
        let isCurrent = step == item
        let isCompleted = step > item
        return HStack(spacing: 12) {
            ZStack {
                Circle()
                    .fill(isCurrent || isCompleted ? AppPalette.primary : Color.white.opacity(0.10))
                    .frame(width: 30, height: 30)
                if isCompleted {
                    Image(systemName: "checkmark")
                        .font(.caption.weight(.bold))
                        .foregroundStyle(.white)
                } else {
                    Text("\(item)")
                        .font(.caption.weight(.bold))
                        .foregroundStyle(isCurrent ? .white : AppPalette.onBrandMuted)
                }
            }
            Text(titles[item - 1])
                .font(.callout.weight(isCurrent ? .semibold : .regular))
                .foregroundStyle(isCurrent ? AppPalette.onBrand : AppPalette.onBrandMuted)
        }
    }

    private var header: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                VStack(alignment: .leading, spacing: 4) {
                    Text(model.uiText("配置 AI 模型"))
                        .font(.title2.weight(.semibold))
                    Text(model.uiText("完成连接后即可使用智能问答和报告分析"))
                        .font(.callout)
                        .foregroundStyle(AppPalette.textMuted)
                }
                Spacer()
                Text(model.uiText("第 %d / 4 步", step))
                    .font(.caption.weight(.semibold))
                    .foregroundStyle(AppPalette.primaryStrong)
            }
            ProgressView(value: Double(step), total: 4)
                .tint(AppPalette.primary)
        }
        .padding(.horizontal, 36)
        .padding(.vertical, 24)
        .background(AppPalette.card)
    }

    @ViewBuilder
    private var stepContent: some View {
        switch step {
        case 1: providerStep
        case 2: modelStep
        case 3: connectionStep
        default: verificationStep
        }
    }

    private var providerStep: some View {
        VStack(alignment: .leading, spacing: 22) {
            stepHeading(model.uiText("选择模型厂商"), subtitle: model.uiText("请选择你已经开通 API 服务的厂商"))
            LazyVGrid(columns: [GridItem(.flexible()), GridItem(.flexible()), GridItem(.flexible())], spacing: 14) {
                ForEach(LLMProvider.allCases) { item in
                    Button {
                        provider = item
                        selectedModel = item.defaultModel
                        customModel = ""
                        endpoint = item.defaultEndpoint
                        apiKey = ""
                        testResult = nil
                    } label: {
                        VStack(alignment: .leading, spacing: 16) {
                            HStack {
                                Image(systemName: item.icon)
                                    .font(.title3.weight(.semibold))
                                    .foregroundStyle(provider == item ? .white : AppPalette.primaryStrong)
                                Spacer()
                                Image(systemName: provider == item ? "checkmark.circle.fill" : "circle")
                                    .foregroundStyle(provider == item ? .white : AppPalette.textSubtle)
                            }
                            Text(item.title)
                                .font(.headline)
                                .foregroundStyle(provider == item ? .white : AppPalette.text)
                            Text(item.subtitle)
                                .font(.caption)
                                .foregroundStyle(provider == item ? Color.white.opacity(0.74) : AppPalette.textMuted)
                                .fixedSize(horizontal: false, vertical: true)
                        }
                        .padding(18)
                        .frame(maxWidth: .infinity, minHeight: 142, alignment: .leading)
                        .background(provider == item ? AppPalette.primary : AppPalette.card)
                        .clipShape(RoundedRectangle(cornerRadius: 8, style: .continuous))
                        .overlay {
                            RoundedRectangle(cornerRadius: 8, style: .continuous)
                                .stroke(provider == item ? AppPalette.primaryStrong.opacity(0.28) : AppPalette.border)
                        }
                    }
                    .buttonStyle(.plain)
                }
            }
        }
    }

    private var modelStep: some View {
        VStack(alignment: .leading, spacing: 22) {
            stepHeading(model.uiText("选择具体模型"), subtitle: model.uiText("模型列表遵循 %@ 的接口规范", provider.title))
            VStack(alignment: .leading, spacing: 10) {
                Text(model.uiText("模型"))
                    .font(.caption.weight(.semibold))
                    .foregroundStyle(AppPalette.textMuted)
                Picker(model.uiText("模型"), selection: $selectedModel) {
                    ForEach(provider.modelOptions) { option in
                        Text("\(option.title) · \(option.model)").tag(option.model)
                    }
                    Text(model.uiText("自定义模型 ID…")).tag(onboardingCustomModel)
                }
                .pickerStyle(.menu)
                .labelsHidden()
                .frame(maxWidth: 520, alignment: .leading)

                if selectedModel == onboardingCustomModel {
                    TextField(model.uiText("输入厂商模型 ID"), text: $customModel)
                        .textFieldStyle(LightFieldStyle())
                        .frame(maxWidth: 520)
                }
            }
            .padding(20)
            .background(AppPalette.card)
            .clipShape(RoundedRectangle(cornerRadius: 8, style: .continuous))
            .overlay { RoundedRectangle(cornerRadius: 8).stroke(AppPalette.border) }
        }
    }

    private var connectionStep: some View {
        VStack(alignment: .leading, spacing: 22) {
            stepHeading(model.uiText("填写连接信息"), subtitle: model.uiText("API Key 初始为空，需要使用者自行填写"))
            VStack(alignment: .leading, spacing: 18) {
                onboardingFieldLabel(model.uiText("API 地址"))
                TextField(provider.defaultEndpoint, text: $endpoint)
                    .textFieldStyle(LightFieldStyle())
                    .font(.callout.monospaced())

                onboardingFieldLabel(model.uiText("API Key"))
                HStack {
                    Group {
                        if isKeyVisible {
                            TextField(provider.placeholder, text: $apiKey)
                        } else {
                            SecureField(provider.placeholder, text: $apiKey)
                        }
                    }
                    .textFieldStyle(.plain)
                    .font(.callout.monospaced())
                    Button {
                        isKeyVisible.toggle()
                    } label: {
                        Image(systemName: isKeyVisible ? "eye" : "eye.slash")
                    }
                    .buttonStyle(.plain)
                    .help(isKeyVisible ? model.text(.hideApiKey) : model.text(.showApiKey))
                }
                .padding(.horizontal, 11)
                .frame(height: 38)
                .background(AppPalette.card)
                .clipShape(RoundedRectangle(cornerRadius: 7, style: .continuous))
                .overlay { RoundedRectangle(cornerRadius: 7).stroke(AppPalette.border) }

                Link(destination: provider.keyURL) {
                    Label(model.uiText("前往 %@ 获取 API Key", provider.title), systemImage: "arrow.up.right.square")
                        .font(.caption)
                }
            }
            .padding(22)
            .frame(maxWidth: 620)
            .background(AppPalette.card)
            .clipShape(RoundedRectangle(cornerRadius: 8, style: .continuous))
            .overlay { RoundedRectangle(cornerRadius: 8).stroke(AppPalette.border) }
        }
        .onChange(of: endpoint) { _, _ in testResult = nil }
        .onChange(of: apiKey) { _, _ in testResult = nil }
    }

    private var verificationStep: some View {
        VStack(alignment: .leading, spacing: 22) {
            stepHeading(model.uiText("验证连接"), subtitle: model.uiText("测试成功后才会把配置写入本机加密存储"))
            VStack(alignment: .leading, spacing: 14) {
                reviewRow(model.uiText("厂商"), provider.title)
                reviewRow(model.uiText("模型"), effectiveModel)
                reviewRow(model.uiText("API 地址"), endpoint)
                reviewRow("API Key", model.uiText("已填写，不显示明文"))
            }
            .padding(20)
            .frame(maxWidth: 620)
            .background(AppPalette.card)
            .clipShape(RoundedRectangle(cornerRadius: 8, style: .continuous))
            .overlay { RoundedRectangle(cornerRadius: 8).stroke(AppPalette.border) }

            if let testResult {
                Label(testResult.message, systemImage: testResult.configured ? "checkmark.circle.fill" : "xmark.circle.fill")
                    .font(.callout)
                    .foregroundStyle(testResult.configured ? AppPalette.success : AppPalette.danger)
                    .padding(14)
                    .frame(maxWidth: 620, alignment: .leading)
                    .background((testResult.configured ? AppPalette.success : AppPalette.danger).opacity(0.08))
                    .clipShape(RoundedRectangle(cornerRadius: 8, style: .continuous))
            }

            Button {
                Task { await testConnection() }
            } label: {
                HStack(spacing: 8) {
                    if isTesting { ProgressView().controlSize(.small) } else { Image(systemName: "powerplug") }
                    Text(isTesting ? model.uiText("正在测试") : model.text(.testConnection))
                }
            }
            .buttonStyle(SecondaryActionButtonStyle())
            .disabled(isTesting || isSaving)
        }
    }

    private var navigation: some View {
        HStack {
            if step > 1 {
                Button {
                    step -= 1
                    testResult = nil
                } label: {
                    Label(model.uiText("上一步"), systemImage: "chevron.left")
                }
                .buttonStyle(SecondaryActionButtonStyle())
            }
            Spacer()
            if step < 4 {
                Button {
                    step += 1
                } label: {
                    Label(model.uiText("下一步"), systemImage: "chevron.right")
                }
                .buttonStyle(PrimaryActionButtonStyle())
                .disabled(!canContinue)
            } else {
                Button {
                    Task { await saveAndEnter() }
                } label: {
                    HStack(spacing: 8) {
                        if isSaving { ProgressView().controlSize(.small) } else { Image(systemName: "checkmark") }
                        Text(isSaving ? model.uiText("正在保存") : model.uiText("保存并进入"))
                    }
                }
                .buttonStyle(PrimaryActionButtonStyle())
                .disabled(isSaving || isTesting || testResult?.configured != true)
            }
        }
        .padding(.horizontal, 36)
        .frame(height: 76)
        .background(AppPalette.card)
    }

    private func stepHeading(_ title: String, subtitle: String) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(title).font(.title3.weight(.semibold))
            Text(subtitle).font(.callout).foregroundStyle(AppPalette.textMuted)
        }
    }

    private func onboardingFieldLabel(_ title: String) -> some View {
        Text(title).font(.caption.weight(.semibold)).foregroundStyle(AppPalette.textMuted)
    }

    private func reviewRow(_ title: String, _ value: String) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: 16) {
            Text(title)
                .font(.caption.weight(.semibold))
                .foregroundStyle(AppPalette.textMuted)
                .frame(width: 76, alignment: .leading)
            Text(value)
                .font(.callout)
                .foregroundStyle(AppPalette.text)
                .textSelection(.enabled)
        }
    }

    private var effectiveModel: String {
        selectedModel == onboardingCustomModel
            ? customModel.trimmingCharacters(in: .whitespacesAndNewlines)
            : selectedModel
    }

    private var canContinue: Bool {
        switch step {
        case 1:
            return true
        case 2:
            return !effectiveModel.isEmpty
        case 3:
            let validEndpoint = endpoint.hasPrefix("http://") || endpoint.hasPrefix("https://")
            return validEndpoint && !apiKey.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
        default:
            return testResult?.configured == true
        }
    }

    private var payload: LLMConfigPayload {
        LLMConfigPayload(
            provider: provider.rawValue,
            model: effectiveModel,
            endpoint: endpoint.trimmingCharacters(in: .whitespacesAndNewlines),
            apiKey: apiKey.trimmingCharacters(in: .whitespacesAndNewlines),
            enabled: true,
            maxTokens: 1800,
            temperature: 0.25,
            topP: 0.9,
            timeoutMs: 60000,
            reasoningEffort: provider == .custom ? "xhigh" : nil,
            disableResponseStorage: provider == .custom ? true : nil
        )
    }

    private func hydrateFromConfig() {
        guard !didHydrate, let config = model.llmConfig else { return }
        provider = LLMProvider(rawValue: config.provider) ?? .openai
        selectedModel = provider.modelOptions.contains(where: { $0.model == config.model }) ? config.model : onboardingCustomModel
        customModel = selectedModel == onboardingCustomModel ? config.model : ""
        endpoint = config.endpoint?.isEmpty == false ? config.endpoint ?? provider.defaultEndpoint : provider.defaultEndpoint
        apiKey = ""
        didHydrate = true
    }

    private func testConnection() async {
        testResult = await model.testLLMConfig(payload)
    }

    private func saveAndEnter() async {
        guard testResult?.configured == true else { return }
        await model.saveLLMConfig(payload)
    }
}
