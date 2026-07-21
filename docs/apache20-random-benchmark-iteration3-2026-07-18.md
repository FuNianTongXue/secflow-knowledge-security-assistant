# SecFlow Java 代码审计引擎随机 Apache 项目基准记录

日期：2026-07-18

## 测试范围

- 项目清单：`config/evaluation/apache-high-star-java-random-20-2026-07-18.json`
- 样本：20 个随机抽取的 Apache 高星 Java 项目，复用 100 项目池中的固定 commit。
- 真实项目静态扫描结果：
  - 旧规则：`docs/apache100-java-static-iteration2-results.json`
  - 新规则：`docs/apache20-random-java-static-iteration3-response-rule-results.json`
- OWASP 新规则回归：
  - 全量：`docs/apache100-owasp-engine-iteration3-response-rule-results.json`
  - Holdout：`docs/apache100-owasp-engine-iteration3-response-rule-holdout-results.json`
- LLM 候选复核结果：`docs/apache20-random-java-llm-triage-2026-07-18-results.json`
- OWASP Benchmark 结果：`docs/apache100-owasp-llm-incremental-iteration2-results.json`

普通开源项目没有完整漏洞 ground truth，因此这部分只用于观察候选噪声、规则错配和复核稳定性；准确率、召回率、F1 仍以 OWASP Benchmark 为主。

## OWASP Benchmark 指标

| 策略 | TP | FP | TN | FN | Precision | Recall | F1 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 基线引擎 | 663 | 100 | 1225 | 752 | 0.868938 | 0.468551 | 0.608815 |
| iteration2 引擎 | 1074 | 323 | 1002 | 341 | 0.768790 | 0.759011 | 0.763869 |
| LLM strict | 1028 | 104 | 1221 | 387 | 0.908127 | 0.726502 | 0.807224 |
| LLM review | 1058 | 104 | 1221 | 357 | 0.910499 | 0.747703 | 0.821110 |

Holdout 子集：

| 策略 | TP | FP | TN | FN | Precision | Recall | F1 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 基线引擎 | 178 | 23 | 364 | 208 | 0.885572 | 0.461140 | 0.606474 |
| iteration2 引擎 | 285 | 102 | 285 | 101 | 0.736434 | 0.738342 | 0.737387 |
| LLM strict | 270 | 25 | 362 | 116 | 0.915254 | 0.699482 | 0.792952 |
| LLM review | 278 | 25 | 362 | 108 | 0.917492 | 0.720207 | 0.806967 |

## 随机 20 个 Apache 项目复核

LLM 对旧规则抽样候选复核：

- 候选数：96
- 已复核：96
- 完成状态：true
- 失败批次：0
- 判定分布：
  - confirmed：2
  - uncertain：9
  - rejected：85
- 单次候选平均延迟：约 13.1s

这个结果说明真实项目里主要问题不是引擎不可用，而是部分规则在大型工程中噪声较高，需要继续利用 LLM 复核结果反哺规则。

## 本轮已做规则优化

修改文件：`config/semgrep/java-security.yml`

优化点：收紧 `secflow.java.http-response-splitting` 的 sink 匹配范围。旧规则会把任意对象的 `setHeader/addHeader/sendRedirect` 都当成 HTTP 响应头，例如 SMTP/MIME 邮件头、出站 HTTP 请求头、客户端 SDK header builder。新规则要求接收者变量名具备 HTTP 响应语义，例如 `response/resp/reply/exchange`。

效果：

- 20 项目唯一候选从 1038 降到 1015，减少 23 条。
- CWE-113 候选减少 22 条。
- 没有新增候选。
- 被移除候选中，15 条已被上一轮 LLM 判定为 rejected，其余 8 条未进入抽样复核，但路径语义也主要是出站请求头或客户端头。
- OWASP Benchmark 回归指标与 iteration2 完全一致：
  - 全量：TP 1074 / FP 323 / TN 1002 / FN 341 / F1 0.763869。
  - Holdout：TP 285 / FP 102 / TN 285 / FN 101 / F1 0.737387。

## 下一轮优化建议

1. 日志注入规则继续区分外部输入与内部数值/对象日志，优先处理 CWE-117 的 rejected 样本。
2. 弱随机规则需要判断随机数用途，仅对 token、session、key、nonce、password、salt 等安全敏感上下文保持高危提示。
3. 路径遍历规则需要识别 `normalize/toRealPath/startsWith` 等目录约束，降低通用工具方法误报。
4. 对 50k 方法以上的大仓库采用模块切片/分块 CFG-DFG 分析，避免为了稳定性触发整体跳过。
5. 继续固定 OWASP Benchmark 作为量化指标，用真实 Apache 项目作为噪声回归集。
