# AST/CFG/DFG + Semgrep 核心迭代记录：iteration7

日期：2026-07-18

## 本轮目标

继续执行“随机 Apache/GitHub Java 项目扫描 → OWASP Benchmark 硬回归 → 根据真实项目噪声优化核心引擎”的闭环。本轮只调整 mac/C 端项目里的扫描核心与评测资产，不涉及 B 端。

## 样本与基线

随机项目清单：`config/evaluation/apache-high-star-java-random-20-iteration4-2026-07-18.json`

对照基线：

- 静态规则基线：`docs/apache20-random-java-static-iteration5-source-filter-results.json`
- 跨方法基线：`docs/apache20-random-java-flow-iteration6-chunked-results.json`
- OWASP 全量基线：`docs/apache100-owasp-engine-iteration6-chunked-results.json`
- OWASP Holdout 基线：`docs/apache100-owasp-engine-iteration6-chunked-holdout-results.json`

## 发现的问题

真实 Apache 项目里出现了几类高频噪声：

1. `Map.Entry.getValue()`、内部 accumulator、普通业务对象值被当成外部输入，制造大量日志注入候选。
2. `HttpClient.execute(request)` 被未类型化 SQL sink 误识别成 `Statement.execute(sql)`。
3. `Pattern.compile(regex)` 被未类型化 XPath sink 误识别成 `XPath.compile(expr)`。
4. `examples/` 示例代码仍进入生产扫描，尤其影响 Beam 这类示例丰富的仓库。
5. 将所有 `String` 方法参数都视为外部输入虽然有利于 Benchmark 召回，但会在真实项目中放大噪声。

## 修改内容

### 生产源码过滤

修改：`app/source_filter.py`

- 新增 `examples/` 目录过滤。
- 保留 `com/example/...` 这类普通包名，不把包名里的 `example` 误判成示例目录。

新增/更新测试：`tests/test_source_filter.py`

### Java Semgrep 规则收紧

修改：`config/semgrep/java-security.yml`

- SQL / Path / LDAP / XPath：
  - 增加 `request.getParameterValues(...)`。
  - 增加精确的 `request.getParameterNames()` → `nextElement()` 外部输入路径。
  - 对 Cookie/Header 枚举读取收紧变量名，避免任意 `.getValue()` / `.nextElement()` 被当作外部来源。
- SQL sink：
  - 未类型化 `$STMT.execute/query/update(...)` 仅在变量名包含 `stmt` / `statement` 时命中。
  - Spring JDBC sink 仅在变量名包含 `jdbc` / `template` 时命中。
  - 避免 `HttpClient.execute(request)` 被误判为 SQL。
- XPath sink：
  - 未类型化 sink 仅允许变量名包含 `xpath` 或常见缩写 `xp`。
  - 避免 `Pattern.compile(regex)` 被误判为 XPath。

新增测试：`tests/test_semgrep_rule_tightening.py`

- `HttpClient.execute(new HttpGet(url))` 不再触发 SQL 注入。
- `Pattern.compile(regex)` 不再触发 XPath 注入。
- `XPath xp.compile(taintedExpression)` 仍能触发 XPath 注入。

## OWASP Benchmark 回归

第一版过度收紧后出现明显 Recall 损失：

| 范围 | Precision | Recall | F1 |
| --- | ---: | ---: | ---: |
| 全量 | 0.780728 | 0.727208 | 0.753018 |
| Holdout | 0.743169 | 0.704663 | 0.723404 |

原因：删除任意 `String` 参数来源过于激进，SQL / Path traversal / XPath 的 Benchmark 召回下降。

调整为“真实入口保留 + 误识别 sink 收紧”后，最终结果：

结果文件：

- 全量：`docs/apache100-owasp-engine-iteration7-source-sink-balanced-results.json`
- Holdout：`docs/apache100-owasp-engine-iteration7-source-sink-balanced-holdout-results.json`

| 范围 | TP | FP | TN | FN | Precision | Recall | F1 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| iteration6 全量基线 | 1074 | 323 | 1002 | 341 | 0.768790 | 0.759011 | 0.763869 |
| iteration7 全量 | 1084 | 333 | 992 | 331 | 0.764996 | 0.766078 | 0.765537 |
| iteration6 Holdout 基线 | 285 | 102 | 285 | 101 | 0.736434 | 0.738342 | 0.737387 |
| iteration7 Holdout | 287 | 104 | 283 | 99 | 0.734015 | 0.743523 | 0.738738 |

结论：最终版本没有用真实项目降噪换取 Benchmark 漏报；全量与 Holdout F1 都小幅提升。

## 20 个 Apache 项目静态扫描回归

结果文件：`docs/apache20-random-java-static-iteration7-source-sink-balanced-results.json`

| 指标 | iteration5 | iteration7 | 变化 |
| --- | ---: | ---: | ---: |
| 完成项目 | 20/20 | 20/20 | 持平 |
| Java 文件 | 59,740 | 59,385 | -355 |
| 唯一候选 | 2,788 | 697 | -2,091 |
| Findings | 2,793 | 699 | -2,094 |
| 总耗时 | 1,361.77s | 1,375.12s | +13.35s |

主要下降：

| CWE | iteration5 | iteration7 | 变化 |
| --- | ---: | ---: | ---: |
| CWE-22 路径穿越 | 810 | 11 | -799 |
| CWE-117 日志注入 | 892 | 112 | -780 |
| CWE-89 SQL 注入 | 309 | 0 | -309 |
| CWE-643 XPath 注入 | 162 | 19 | -143 |
| CWE-90 LDAP 注入 | 50 | 0 | -50 |

抽查确认：

- Beam `examples/java/.../TfIdf.java` 示例日志候选不再进入生产扫描。
- Beam `Regex.java` 的 `Pattern.compile(regex)` 不再被识别为 XPath sink。
- 之前把 HTTP 客户端请求执行误识别为 SQL sink 的候选已消失。

说明：普通 Apache 开源项目没有标准漏洞标签，以上数据只能代表候选噪声与覆盖变化，不能直接声称真实误报率/漏报率。真实 FP/FN/Precision/Recall 仍以 OWASP Benchmark 统计为准。

## 20 个 Apache 项目 AST/CFG/DFG 跨方法回归

结果文件：`docs/apache20-random-java-flow-iteration7-source-sink-balanced-results.json`

| 指标 | iteration6 | iteration7 | 变化 |
| --- | ---: | ---: | ---: |
| 完成项目 | 20/20 | 20/20 | 持平 |
| limit_exceeded | 0 | 0 | 持平 |
| Java 文件 | 59,740 | 59,385 | -355 |
| review_candidates | 1,205 | 1,205 | 持平 |
| high_confidence_cross_method_candidates | 644 | 644 | 持平 |
| unique_high_confidence_cross_method_candidates | 315 | 315 | 持平 |
| combined_unique_candidates | 3,067 | 3,018 | -49 |
| 总耗时 | 583.67s | 480.52s | -103.15s |

模块切片仍正常工作：

- Geode：32 个模块切片
- Hadoop：72 个模块切片
- Doris：72 个模块切片
- skipped_chunk_count：0

## 当前结论

1. 本轮把真实项目里的低质量 source/sink 噪声明显压低。
2. OWASP Benchmark 全量与 Holdout F1 均小幅提升，说明没有用漏报换降噪。
3. AST/CFG/DFG 跨方法候选保持稳定，模块切片继续覆盖大仓库。
4. `examples/` 过滤降低了 Beam 等项目的非生产代码干扰，同时保留 `com/example` 包名。

## 下一轮建议

1. 对剩余 112 条日志注入候选做“日志上下文置信度”分层：Web 输入/认证头高优先级，内部对象、计数器、固定枚举低优先级。
2. 对剩余弱随机候选区分安全敏感上下文和普通负载均衡/采样/测试辅助随机。
3. 为 SQL/LDAP 在真实 Web Controller 项目里补充更精准的框架入口识别，例如 Spring `@RequestParam`、JAX-RS `@QueryParam`。
4. 继续随机挑选新的 Apache Java 项目批次，维持 OWASP Benchmark 作为硬回归门禁。
