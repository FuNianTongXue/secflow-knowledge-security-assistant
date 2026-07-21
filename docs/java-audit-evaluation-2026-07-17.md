# Java 自动化代码审计评估（2026-07-17）

## 结论

真实 CodeQL CLI 明显优于项目原有的启发式降级规则，但不能据此宣称“无误报”。在 OWASP BenchmarkJava 1.2 的 2,740 个带标准答案测试中：

| 引擎/规则集 | TP | FP | TN | FN | 误报率 FPR | 漏报率 FNR | 精确率 | 召回率 | F1 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| CodeQL `java-security-extended` | 1,415 | 531 | 794 | 0 | 40.08% | 0.00% | 72.71% | 100.00% | 84.20% |
| CodeQL `java-code-scanning` | 1,160 | 319 | 1,006 | 255 | 24.08% | 18.02% | 78.43% | 81.98% | 80.17% |
| SecFlow 内置降级规则（修正后） | 210 | 185 | 1,140 | 1,205 | 13.96% | 85.16% | 53.16% | 14.84% | 23.20% |

降级规则的总体误报率较低是因为它完全不覆盖 9 个 Benchmark 类别，不能理解为质量更高。其已覆盖类别仍有明显问题：命令注入 FPR 24.00%、FNR 73.81%；SQL 注入 FPR 66.81%、FNR 34.93%。真实 CLI 成功时不应混入降级规则结果。

## 测试基线

- CodeQL CLI：2.25.1（macOS ARM64）
- Java query pack：`codeql/java-queries@1.11.0`
- 标准指标基线：OWASP BenchmarkJava 1.2，commit `79b9bd6177e07991a9c11dc19e457c840e229931`
- 规则与标准答案按测试文件编号和 CWE 同时匹配；同一测试文件中其他 CWE 的告警不计作该用例命中
- CodeQL buildless 与完整 Maven 构建各运行一次，两者均产生 4,695 条扩展套件结果，混淆矩阵完全一致
- 普通开源项目没有完整 ground truth，因此只报告覆盖率、性能、发现类型和人工复核，不伪造精确误报率或漏报率

## 高星项目规模测试

测试输入镜像只保留客户端允许的 `.java` 与 `pom.xml`。数据库创建使用 `build-mode=none`，Maven 依赖图不可用时由 CodeQL 按包名推断依赖。

| 项目 | 固定 commit | Java/POM | 数据库创建 | 规则分析 | 提取覆盖 | 原始/去重发现 |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| spring-projects/spring-petclinic | `f182358d02e4a68e52bdbabf55ca7800288511e7` | 49/1 | 64.29s | 20.64s | 44/49 | 2/2 |
| macrozheng/mall | `0504e86b1f1b6f1b8aa6a734d37a90fb67346be7` | 524/8 | 152.73s | 25.14s | 524/524 | 20/17 |
| alibaba/arthas | `86d01c09da196c3f6cd29ce1bde77044edb67d42` | 1,010/34 | 311.59s | 36.08s | 1,006/1,010 | 73/66 |
| apache/dubbo | `d0bf5c36d092da8067b15a1d1d00884a8c399e8e` | 4,048/119 | 421.14s | 57.85s | 3,957/4,048 | 163/162 |

真实项目复核要点：

- Petclinic 的 2 条均为请求页码未经下界校验后执行 `page - 1`，代码证据成立。
- mall 发现未校验分页算术、用户值日志注入、JWT 敏感信息日志和关闭 CSRF；其中 CSRF 是否可利用取决于无状态 JWT 是否完全不使用 Cookie，需要上下文确认。
- Arthas 同时出现有效的日志注入、SSRF、路径和分页风险，也出现测试代码中的相对 `bash`、本地 CLI 自选路径、已在 `finally` 解锁等明显不适用于生产漏洞结论的告警。
- Dubbo 发现 XSS、正则注入、Zip Slip、SSRF、响应拆分、敏感日志等高价值路径；也包含测试目录告警、兼容性算术和需要并发语义复核的锁告警。
- 真实项目应排除 `src/test`、示例和实验目录，并结合部署信任边界复核。没有项目维护方的标准答案，不能把“未被人工确认”直接当作误报，也不能据此计算漏报率。

## 已落地修正

1. 真实 CLI 成功完成时以官方 SARIF 为准；只有 CLI 缺失、失败或超时才使用内置降级规则。
2. CodeQL 临时工程现在同时包含代码和 POM，不再静默丢弃 POM。
3. 附件上限由 8 提升到 64；SARIF/报告默认上限由 20 提升到 500，可通过 `SECFLOW_STATIC_MAX_FINDINGS` 调整。
4. 按“规则 + 文件 + 行号”去重，同一行的不同漏洞类型仍分别保留。
5. 官方 `security-severity` 数字按 CVSS 阈值转换为 CRITICAL/HIGH/MEDIUM/LOW，并提取 CWE，避免前端显示“未知”。
6. 单个 CodeQL 阶段超时由 45 秒提高到 180 秒；macOS 附件问答请求超时提高到 420 秒。
7. 降级规则不再把 `Properties.load()`、领域对象的 `.Statement` 或通用 `.execute()` 当作漏洞，并且无外部输入 source 时不再仅凭 sink 报警。
8. 授权 bundle 构建会校验 CLI、Java extractor、查询套件、全部 query pack 依赖和包内符号链接，复制后再次校验。

## 发布许可阻塞

本机 CodeQL 标准许可明确禁止向第三方分享、发布、分发或提供该软件使用。GitHub Advanced Security 付费条款放宽的是私有代码分析用途，并不自动取消再分发禁令。

因此当前发布流程不会把 Homebrew 的 CodeQL 复制到 `dist/SecFlow.app`。只有取得 GitHub 书面再分发授权后，才可提供授权 bundle，并设置：

```bash
SECFLOW_INCLUDE_CODEQL_BUNDLE=1 \
SECFLOW_CODEQL_REDISTRIBUTION_AUTHORIZED=1 \
CODEQL_LICENSE_GRANT_PATH=/secure/path/github-codeql-redistribution-grant.pdf \
CODEQL_BUNDLE_PATH=/secure/path/authorized-codeql-bundle \
bash scripts/build_macos_app.sh
```

## 后续工程要求

- 超过 500 个文件的项目数据库创建已达到 153 到 421 秒，不能继续依赖同步聊天请求。应改成后台审计任务、进度状态和可恢复数据库缓存。
- 64 个附件适合代码片段/模块审计，不等于完整仓库审计。完整项目应提供目录选择与后台扫描，不应把数千文件直接塞进一次 JSON 问答。
- 默认继续使用 `java-security-extended` 可保留最高召回；若更重视日常噪声，可增加内部“快速扫描”策略使用 `java-code-scanning`，但必须接受 18.02% 的 Benchmark 漏报率。
- 应建立项目级抑制策略：默认排除测试/示例目录、按规则记录人工处置、对部署信任边界做可审计标注，并持续回归 OWASP Benchmark。
