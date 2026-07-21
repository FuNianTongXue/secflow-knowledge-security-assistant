# AST/CFG/DFG + Semgrep 核心迭代记录：iteration8

日期：2026-07-18

## 本轮目标

继续按“随机 Apache Java 项目扫描 → OWASP Benchmark 硬回归 → 真实项目噪声定位 → 核心扫描优化”的闭环推进。本轮重点处理：

1. 示例/集成测试代码误进入生产审计。
2. 弱随机候选在报告里缺少安全上下文分层，普通采样随机和安全令牌随机混在一起。

## 修改内容

### 1. 生产源码过滤增强

修改文件：`app/source_filter.py`

新增过滤：

- `integration` / `src/integration/**`
- `it/**/src/main/**`
- `*dunit*` 分布式单测模块
- 深层示例包路径：
  - `.../src/main/java/*/*/*/**/example/**`
  - `.../demo/**`
  - `.../sample/**`
  - `.../tutorial/**`

保留：

- `src/main/java/com/example/...`
- `src/main/java/com/secflow/demo/...`

这样避免把常见 Java 包名 `com.example` 当成示例代码误删。

测试覆盖：`tests/test_source_filter.py`

### 2. 弱随机报告层上下文分层

修改文件：`app/semgrep_tool.py`

弱随机不再一律作为同等优先级展示，而是按上下文分层：

- `high`：明确出现在 password / secret / session / auth / jwt / cookie / signature / token / api key 等安全语义中。
- `low`：采样、退避、jitter、padding、shuffle、partition、bucket、synthetic、fixture、benchmark、demo/example/tutorial 等普通随机上下文。
- `medium`：用途未知，需要结合调用方确认。

修正误判：

- `samplingToken` 这类采样变量不再因为包含 `token` 被顶到高优先。
- `SaltJoin` / `DEFAULT_SALT_VALUE` 这类 SQL 分桶/倾斜处理语义不再因为包含 `salt` 被顶到高优先。
- `SecureRandom` 出现在附近上下文时，不会把同一段里的 `new Random()` 自动判为高优先。

测试覆盖：`tests/test_semgrep_reports.py`

### 3. 报告输出字段优化

修改文件：`app/reports.py`

- 代码漏洞条目存在 `priority` 时才显示“优先级”。
- 弱随机报告展示“安全上下文”和“分析备注”，解释为什么是高/中/低优先级。

## OWASP Benchmark 回归

结果文件：

- 全量：`docs/apache100-owasp-engine-iteration8-context-filter-results.json`
- Holdout：`docs/apache100-owasp-engine-iteration8-context-filter-holdout-results.json`

| 范围 | TP | FP | TN | FN | Precision | Recall | F1 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| iteration7 全量 | 1084 | 333 | 992 | 331 | 0.764996 | 0.766078 | 0.765537 |
| iteration8 全量 | 1084 | 333 | 992 | 331 | 0.764996 | 0.766078 | 0.765537 |
| iteration7 Holdout | 287 | 104 | 283 | 99 | 0.734015 | 0.743523 | 0.738738 |
| iteration8 Holdout | 287 | 104 | 283 | 99 | 0.734015 | 0.743523 | 0.738738 |

结论：本轮没有牺牲 OWASP 召回和 F1。

## 20 个 Apache 项目静态扫描回归

最终结果文件：`docs/apache20-random-java-static-iteration8-production-context-results.json`

对照：`docs/apache20-random-java-static-iteration7-source-sink-balanced-results.json`

| 指标 | iteration7 | iteration8 | 变化 |
| --- | ---: | ---: | ---: |
| 完成项目 | 20/20 | 20/20 | 持平 |
| Java 文件 | 59,385 | 58,905 | -480 |
| Findings | 699 | 678 | -21 |
| 唯一候选 | 697 | 677 | -20 |
| Semgrep errors | 78 | 66 | -12 |
| 总耗时 | 1,375.12s | 1,291.88s | -83.24s |

主要变化：

| CWE | iteration7 | iteration8 | 变化 |
| --- | ---: | ---: | ---: |
| CWE-330 弱随机 | 297 | 278 | -19 |
| CWE-117 日志注入 | 112 | 111 | -1 |
| CWE-78 命令执行 | 24 | 23 | -1 |
| CWE-328 弱哈希 | 50 | 48 | -2 |
| CWE-611 XXE | 14 | 13 | -1 |
| CWE-79 XSS | 85 | 88 | +3 |

说明：普通 Apache 项目没有标准漏洞标签，以上不能直接声称真实 FP/FN，只能说明候选噪声和扫描覆盖变化；真实 Precision/Recall 仍以 OWASP Benchmark 为准。

## 弱随机上下文分层结果

在 iteration8 的 278 条弱随机候选中，报告层分布为：

| 优先级 | 数量 | 含义 |
| --- | ---: | --- |
| high | 11 | 具备较明确安全语义，例如 OAuth、secret provider、认证/密码等上下文 |
| medium | 223 | 用途未知，需要结合调用方确认 |
| low | 44 | 更像采样、shuffle、partition、synthetic、benchmark 等普通随机 |

这不会删除底层证据，但会让报告中心优先展示更值得人工关注的内容。

## AST/CFG/DFG 跨方法回归

最终结果文件：`docs/apache20-random-java-flow-iteration8-production-context-results.json`

本轮运行时显式传入静态 raw 结果目录：

`/tmp/secflow-apache100-evaluation/projects/results-iteration8-production-context`

| 指标 | iteration7 | iteration8 | 变化 |
| --- | ---: | ---: | ---: |
| 完成项目 | 20/20 | 20/20 | 持平 |
| Java 文件 | 59,385 | 58,905 | -480 |
| review_candidates | 1,205 | 1,193 | -12 |
| high_confidence_cross_method_candidates | 644 | 635 | -9 |
| unique_high_confidence_cross_method_candidates | 315 | 310 | -5 |
| limit_exceeded | 0 | 0 | 持平 |
| chunked 项目 | 3 | 3 | 持平 |
| skipped_chunk_count | 0 | 0 | 持平 |

下降主要来自 Iceberg integration 测试和部分示例/测试模块，不是生产路径引擎能力下降。

## 当前结论

1. 本轮将非生产 Java 输入减少 480 个文件。
2. 静态唯一候选减少 20 条，弱随机 raw 候选减少 19 条。
3. 弱随机报告层新增安全上下文分层，商业报告可读性更好。
4. OWASP Benchmark 全量和 Holdout 指标完全保持。
5. AST/CFG/DFG 大仓库模块切片仍正常，limit_exceeded 继续为 0。

## 下一轮建议

1. 对剩余 223 条 medium 弱随机继续识别“负载均衡 / 缓存分区 / 端口选择 / 普通采样”上下文，进一步降低人工审计噪声。
2. 对日志注入增加 CR/LF 规范化识别：已经 replace/normalize 的日志输入不作为高优先级。
3. 扩展 Spring / JAX-RS 参数注解入口，例如 `@RequestParam`、`@PathVariable`、`@QueryParam`，提升真实 Web 项目召回。
4. 继续抽新的 Apache 高星 Java 项目批次做噪声画像，维持 OWASP Benchmark 作为硬门禁。
