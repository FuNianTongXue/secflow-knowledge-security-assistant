# macOS 智能体模块 v1.2.0 发布说明

发布日期：2026-07-21

发布标签：`v1.2.0-macos-agent-trial`

## 发布内容

- 将 SwiftUI macOS 前端与 FastAPI/LangGraph 智能体后端作为可独立构建、运行和测试的模块发布。
- 新增总览、智能问答、安全资讯、知识图谱、漏洞库、报告、设置和首次运行模型配置界面。
- 新增本地优先漏洞情报查询、多源富化、采集器子图、按用户隔离的长期记忆和加密本地存储。
- 新增 Maven/Gradle 依赖解析、Java 跨方法 AST/CFG/DFG 分析，以及 Python、Go、C/C++、Rust、Solidity 文件内数据流分析。
- 内嵌 Semgrep OSS 1.170.0、七种语言的离线安全规则、Tree-sitter 语法模块和第三方许可证。
- 新增后端强制执行的连续 72 小时试用限制，包含 Keychain 双副本、设备/用户绑定、状态篡改和系统时间回拨检测。
- 同时发布 Apple Silicon `arm64` 与 Intel `x86_64` 两个独立构建。

## 下载与校验

| 文件 | 平台 | 大小 | SHA-256 |
| --- | --- | ---: | --- |
| `SecFlow-Trial-3Days-macOS-arm64.zip` | Apple Silicon | 122 MB | `bdc32aa87d1c1308c5b45689a1d169a1903b585367dbc4131801b3f3aacc1f28` |
| `SecFlow-Trial-3Days-macOS-x86_64.zip` | Intel Mac | 124 MB | `6f50ece93287684d556dc501a29ad73552327a4d63949b61fd1572e315e773e1` |

两个客户端最低支持 macOS 14。发布包使用 ad-hoc 签名，未使用 Apple Developer ID 签名或公证；在其他 Mac 首次启动时，可能需要在 Finder 中右键选择“打开”。

## 发布验证

- Python：arm64 与 x86_64 环境各执行 `185` 个测试，全部通过。
- Swift：arm64 与 x86_64 各执行 `23` 个测试，`22` 个通过，`1` 个未配置实时后端的集成测试按预期跳过。
- 静态分析：Semgrep 1.170.0、七套离线规则、七种 Tree-sitter 语法模块和多语言 taint 烟测通过。
- 架构：arm64 应用内 `243` 个 Mach-O 文件全部为 `arm64`；Intel 应用内 `128` 个 Mach-O 文件全部为 `x86_64`。
- 运行：两个包的内嵌后端均通过 `/health`、`/api/trial/status` 和核心 API 启动验收，试用状态为 `active`、时长为 `72h`。
- 产物：两个 ZIP 完整性检查、应用深度签名校验与试用版 `Info.plist` 校验通过。

## 许可证与限制

应用包包含 Semgrep LGPL-2.1、Tree-sitter 与七种语言语法模块 MIT 许可证、D3 ISC 许可证、D3 Sankey BSD-3-Clause 许可证及第三方声明。离线试用限制用于体验控制，不应被视为不可绕过的软件授权或 DRM 机制。
