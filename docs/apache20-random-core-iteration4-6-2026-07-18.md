# AST/CFG/DFG + Semgrep 核心迭代记录

日期：2026-07-18

## 本轮目标

按“随机 GitHub/Apache Java 项目上传测试 → 真实项目结果分析 → 修改核心扫描逻辑 → OWASP Benchmark 回归”的闭环推进，不单独做离线汇报。

## 随机样本

清单：`config/evaluation/apache-high-star-java-random-20-iteration4-2026-07-18.json`

随机种子：`secflow-apache-random-iteration4-2026-07-18`

项目包括 Geode、Kafka、Lucene、HBase、Hadoop、Linkis、Inlong、Iceberg、Doris、JMeter、Calcite、Beam 等 20 个 Apache Java 项目。

## iteration4：当前核心扫描基线

静态规则结果：`docs/apache20-random-java-static-iteration4-core-results.json`

- 完成项目：20/20
- Java 文件：54,248
- 唯一候选：2,498
- 总耗时：1,284.36s
- 高频候选：
  - CWE-117 日志注入：737
  - CWE-22 路径穿越：656
  - CWE-89 SQL 注入：354
  - CWE-330 弱随机：326

跨方法 AST/CFG/DFG 结果：`docs/apache20-random-java-flow-iteration4-core-results.json`

- 完成项目：17/20
- limit_exceeded：2
- warning：1
- 新增高可信跨方法候选：142
- 问题：
  - Geode、Doris 超过 50k 方法上限被整体跳过。
  - Hadoop 评测缓存工作树损坏，源码发现为 0。

## iteration5：生产源码过滤与 checkout 健康检查

修改：

- 新增共享过滤器：`app/source_filter.py`
- 接入客户端静态分析入口：`app/semgrep_tool.py`
- 接入评测脚本：`scripts/evaluate_java_semgrep.py`
- 增加 checkout 脏状态恢复，避免 `/tmp` 评测缓存损坏导致 0 文件。

静态结果：`docs/apache20-random-java-static-iteration5-source-filter-results.json`

直接总量：

- Java 文件：59,740
- 唯一候选：2,788
- 总耗时：1,361.77s

注意：总量上升是因为 Hadoop 从 0 文件恢复到 8,135 个 Java 文件，并新增 549 条候选。排除 Hadoop 后，19 个可比项目的净效果是：

- Java 文件：54,248 → 51,605
- 唯一候选：2,498 → 2,239，减少 259 条
- 总耗时：1,281.48s → 1,179.97s
- 主要下降：
  - CWE-330 弱随机：-103
  - CWE-22 路径穿越：-73
  - CWE-89 SQL 注入：-57
  - CWE-117 日志注入：-24

跨方法结果：`docs/apache20-random-java-flow-iteration5-source-filter-results.json`

- 完成项目：17/20
- limit_exceeded：3
- Hadoop 恢复后进入扫描，但由于 88,501 个方法触发跨方法上限。

## iteration6：大仓库模块切片 AST/CFG/DFG

修改：

- `app/java_flow_analyzer.py`
  - 整仓超过方法上限时，按模块切片运行 AST/CFG/DFG。
  - 模块边界优先按 `*/src/main/*`、`*/src/*` 前缀识别。
  - 切片模式不合并跨模块调用路径，避免用不可靠调用边制造误报。
- `scripts/evaluate_java_flow.py`
  - 透出 chunked/chunk_count/completed_chunk_count/skipped_chunk_count 评测字段。

跨方法结果：`docs/apache20-random-java-flow-iteration6-chunked-results.json`

- 完成项目：20/20
- limit_exceeded：0
- 总 Java 文件：59,740
- 总方法数：563,087
- 总调用边：504,954
- 新增高可信跨方法候选：279
- 相比 iteration5，新增高可信跨方法候选 141 → 279。
- 大仓库恢复：
  - Geode：原 0 → 新增 13 条高可信跨方法候选
  - Hadoop：原 0 → 新增 57 条高可信跨方法候选
  - Doris：原 0 → 新增 68 条高可信跨方法候选

## OWASP Benchmark 回归

结果：

- 全量：`docs/apache100-owasp-engine-iteration6-chunked-results.json`
- Holdout：`docs/apache100-owasp-engine-iteration6-chunked-holdout-results.json`

指标保持不变：

| 范围 | TP | FP | TN | FN | Precision | Recall | F1 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 全量 | 1074 | 323 | 1002 | 341 | 0.768790 | 0.759011 | 0.763869 |
| Holdout | 285 | 102 | 285 | 101 | 0.736434 | 0.738342 | 0.737387 |

结论：生产路径过滤降低真实项目噪声；模块切片提高大仓库跨方法覆盖；两者都没有拉低 OWASP Benchmark 指标。

## 下一轮建议

1. 对日志注入引入日志参数类型过滤：数值、枚举、固定对象计数、内部 metric 不进入高优先级候选。
2. 对路径穿越识别 `normalize/toRealPath/startsWith` 等根目录约束。
3. 对弱随机拆分“安全敏感上下文”和“普通采样/负载均衡/benchmark”，但要单独评估 OWASP CWE-330 召回影响。
4. 将切片模式的 chunk 字段接入报告中心，用户可见为“模块级分析”，不暴露底层引擎名称。
