# SecFlow macOS Client

SecFlowMac 是知识库安全助手的原生 SwiftUI 客户端，最低支持 macOS 14。发布版应用内置 FastAPI/LangGraph 智能体后端，由应用自动启停，不依赖 Docker 或仓库中的独立服务。正式版数据保存在 `~/Library/Application Support/SecFlow`，三天试用版使用隔离目录 `~/Library/Application Support/SecFlow-Trial`。

前端源码位于 `Sources/SecFlowMac`，后端源码位于仓库根目录 `app/`。发布包会把 Python 后端、静态 Web 资源、Semgrep CLI、多语言规则和 Tree-sitter 运行库一起放入 `.app`，用户不需要安装 Python 或扫描工具。

## 开发运行

开发阶段可先在仓库根目录启动后端：

```bash
uvicorn app.main:app --host 127.0.0.1 --port 18081
```

再启动客户端：

```bash
swift run --package-path macos/SecFlowMac
```

开发运行时通过 `SECFLOW_SERVER_URL=http://127.0.0.1:18081` 指定外部服务。构建后的应用使用内置本地服务。

## 构建应用

```bash
python -m pip install -r requirements-macos.txt
bash scripts/build_macos_app.sh
open dist/SecFlow.app
```

脚本会把后端打包到应用资源目录，生成 `dist/SecFlow.app` 并默认进行 ad-hoc 签名。分发给其他设备前，应替换为正式 Developer ID 签名并执行 notarization。

## 三天试用版与双架构构建

Apple Silicon：

```bash
bash scripts/build_macos_trial_app.sh
```

Intel Mac 构建需要 x86_64 Python 环境，不能用 arm64 Python 交叉封装：

```bash
SECFLOW_MACOS_ARCH=x86_64 \
PYTHON_BIN=/path/to/x86_64/venv/bin/python \
bash scripts/build_macos_trial_app.sh
```

输出目录为 `dist-macos-trial/`。试用包使用独立 Bundle ID、回环端口、应用数据目录和 Keychain 服务，不会与正式版数据混用。首次启动后连续可用 72 小时；后端负责到期拦截，SwiftUI 显示实时倒计时和到期锁定界面。

已发布版本：

- [Apple Silicon arm64](https://github.com/FuNianTongXue/secflow-knowledge-security-assistant/releases/download/v1.2.0-macos-agent-trial/SecFlow-Trial-3Days-macOS-arm64.zip)
- [Intel x86_64](https://github.com/FuNianTongXue/secflow-knowledge-security-assistant/releases/download/v1.2.0-macos-agent-trial/SecFlow-Trial-3Days-macOS-x86_64.zip)

### 内嵌静态分析 CLI

发布构建会把 Semgrep OSS CLI、Java/Python/Go/C/C++/Rust/Solidity 离线规则、Tree-sitter 语法模块和 LGPL-2.1/MIT 许可证一起放入应用。规则完全离线运行，显式关闭 metrics、版本检查和在线 Registry；客户无需安装 Homebrew、Python 或其他分析工具。

```bash
.venv/bin/python -m pip install -r requirements-macos.txt
bash scripts/build_macos_app.sh
```

构建脚本会在签名前启动应用内 CLI，并对七种语言的临时文件执行真实 source/sink 或结构规则扫描。CLI、任一语言规则、语法运行库或结果解析缺失都会终止构建。商业发布还需保留 `Contents/Resources/licenses` 下的 Semgrep 与 Tree-sitter 许可证，并按 LGPL-2.1 提供对应 Semgrep 源码获取方式。

## 验证

```bash
swift build --package-path macos/SecFlowMac
swift test --package-path macos/SecFlowMac
```
