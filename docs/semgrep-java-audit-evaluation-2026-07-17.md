# Java 自动化代码审计评估（2026-07-17）

## 结论

SecFlow 的 macOS 客户端使用随应用分发的离线 Java 规则引擎完成方法内 AST/taint 扫描，并增加基于 Java AST、方法摘要、调用图、CFG 和 DFG 的跨方法分析。跨方法结果仅在调用目标唯一解析且路径至少跨过一个项目内方法时自动合并；同方法补充结果不与基础规则重复上报。

在 OWASP BenchmarkJava 1.2 的 2,740 个带标准答案测试中，与上一版相比，Precision、Recall 和误报率同时改善：

| 版本 | TP | FP | TN | FN | FPR | FNR | Precision | Recall | F1 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 上一版基础规则 | 617 | 131 | 1,194 | 798 | 9.89% | 56.40% | 82.49% | 43.60% | 57.05% |
| 当前规则 + 高可信跨方法路径 | 663 | 100 | 1,225 | 752 | 7.55% | 53.14% | 86.89% | 46.86% | 60.88% |

改进来自两部分：动态变量形式的哈希算法无法证明实际使用弱算法，因此不再直接判为漏洞；跨方法层通过常量传播、条件分支裁剪、场景净化器和唯一调用解析补回基础规则遗漏的路径。当前结果仍不能宣传为“完整代码审计”，特别是 SQL、XSS 和路径穿越的漏报率仍然较高。

## 分析方式

- AST：使用 Tree-sitter Java 解析类、字段、方法、参数、赋值、返回值、构造器与调用表达式。
- CFG：记录 `if`、三元表达式、循环、`switch` 和异常路径；对可静态求值的局部常量条件裁剪不可执行分支。
- DFG：固定点计算参数到返回值、参数到 sink、调用参数到被调方法摘要的传播。
- 调用解析：只连接同类调用、已知字段/局部变量类型、明确类名或 `new Class(...)` 接收者；未知接收者不按全局方法名猜测。
- 置信度：只有唯一解析且至少跨过一个项目内调用的路径标为高可信并自动合并。
- 降级：跨方法层失败不会中断基础扫描；诊断只记录阶段错误。
- 离线：关闭指标与版本检查，不访问在线规则仓库，客户无需安装额外工具。
- 安全边界：不执行上传代码，不生成 PoC、载荷或利用步骤。

## Benchmark 明细

标准答案按“测试文件编号 + 预期 CWE”匹配。同一文件中其他 CWE 的候选不计作该类别命中。

| 类别 | CWE | TP | FP | TN | FN | FPR | FNR | Precision | Recall |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 命令注入 | CWE-78 | 23 | 0 | 125 | 103 | 0.00% | 81.75% | 100.00% | 18.25% |
| 弱加密 | CWE-327 | 130 | 0 | 116 | 0 | 0.00% | 0.00% | 100.00% | 100.00% |
| 弱哈希 | CWE-328 | 28 | 0 | 107 | 101 | 0.00% | 78.29% | 100.00% | 21.71% |
| LDAP 注入 | CWE-90 | 17 | 13 | 19 | 10 | 40.63% | 37.04% | 56.67% | 62.96% |
| 路径穿越 | CWE-22 | 55 | 28 | 107 | 78 | 20.74% | 58.65% | 66.27% | 41.35% |
| Cookie Secure | CWE-614 | 36 | 0 | 31 | 0 | 0.00% | 0.00% | 100.00% | 100.00% |
| SQL 注入 | CWE-89 | 64 | 27 | 205 | 208 | 11.64% | 76.47% | 70.33% | 23.53% |
| 信任边界 | CWE-501 | 14 | 2 | 41 | 69 | 4.65% | 83.13% | 87.50% | 16.87% |
| 弱随机数 | CWE-330 | 218 | 0 | 275 | 0 | 0.00% | 0.00% | 100.00% | 100.00% |
| XPath 注入 | CWE-643 | 12 | 8 | 12 | 3 | 40.00% | 20.00% | 60.00% | 80.00% |
| XSS | CWE-79 | 66 | 22 | 187 | 180 | 10.53% | 73.17% | 75.00% | 26.83% |

基础规则产生 1,235 条原始结果；跨方法分析产生 136 条高可信路径。合并后涉及 1,053 个测试文件，错误数为 0。完整机器结果见 `semgrep-owasp-benchmark-results.json`。

## 高星项目测试

20 个项目固定到 `config/evaluation/high-star-java-projects.json` 中的 commit。基础规则扫描 39,259 个生产 Java 文件，得到 1,073 条唯一待复核候选；跨方法层解析 291,054 个方法和 200,501 条调用边，耗时 215.69 秒。

跨方法层共产生 332 条高可信路径；按“场景 + 文件 + sink 行号”去重后为 213 条，其中 23 条与基础规则重合、190 条为新增候选，合并后共 1,263 条唯一候选。普通项目没有逐行标准答案，这些数量不能视为真实漏洞，也不能据此计算误报率或漏报率。

| 项目 | 跨方法唯一 | 与基础重合 | 新增 | 调用边 | 解析错误文件 | 耗时 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| spring-projects/spring-petclinic | 0 | 0 | 0 | 36 | 0 | 0.03s |
| macrozheng/mall | 4 | 2 | 2 | 1,241 | 0 | 2.44s |
| alibaba/arthas | 16 | 5 | 11 | 4,305 | 0 | 4.63s |
| apache/dubbo | 74 | 8 | 66 | 14,775 | 0 | 12.73s |
| alibaba/nacos | 40 | 1 | 39 | 19,481 | 0 | 10.72s |
| alibaba/Sentinel | 9 | 2 | 7 | 4,412 | 0 | 3.11s |
| apache/rocketmq | 1 | 0 | 1 | 17,841 | 1 | 14.74s |
| apache/shardingsphere | 0 | 0 | 0 | 16,305 | 0 | 19.04s |
| apache/skywalking | 1 | 0 | 1 | 8,179 | 0 | 10.22s |
| apache/kafka | 0 | 0 | 0 | 34,532 | 3 | 33.27s |
| seata/seata | 23 | 2 | 21 | 7,630 | 0 | 14.61s |
| netty/netty | 7 | 1 | 6 | 18,191 | 3 | 14.92s |
| google/guava | 0 | 0 | 0 | 527 | 13 | 16.11s |
| ReactiveX/RxJava | 0 | 0 | 0 | 5,741 | 0 | 5.37s |
| halo-dev/halo | 2 | 0 | 2 | 2,092 | 2 | 3.78s |
| iluwatar/java-design-patterns | 2 | 0 | 2 | 984 | 0 | 1.49s |
| TheAlgorithms/Java | 0 | 0 | 0 | 2,042 | 0 | 3.49s |
| spring-projects/spring-framework | 26 | 1 | 25 | 26,138 | 56 | 25.00s |
| zxing/zxing | 0 | 0 | 0 | 2,684 | 0 | 2.91s |
| thingsboard/thingsboard | 8 | 1 | 7 | 13,365 | 0 | 17.08s |

78 个解析错误文件主要位于 Spring Framework、Guava、Netty、Halo、Kafka 和 RocketMQ。最终报告必须保留未解析数量，不能把未扫描文件当成无漏洞。机器结果见 `java-flow-project-results.json` 和 `semgrep-java-project-results.json`。

## 发布判断

1. 当前能力适合附件级和模块级快速审计，可输出文件、行号、风险代码、修复代码及 AST/CFG/DFG 路径。
2. 高可信跨方法路径只代表静态证据更完整，仍需结合依赖版本、业务信任边界和人工复核确认。
3. 动态配置值、反射、框架注入、多态分派、异步消息和运行时生成代码仍是主要漏报来源。
4. 客户端附件上限为 64 个文件；20 项目测试验证底层吞吐，不表示聊天上传入口支持完整仓库。
5. 客户可见报告与接口统一使用中性静态分析名称，不暴露底层实现特征。
6. 商业分发继续保留所用开源组件许可证和第三方声明。

## 复现

```bash
.venv/bin/python scripts/evaluate_java_semgrep.py \
  --manifest config/evaluation/high-star-java-projects.json \
  --output docs/semgrep-java-project-results.json

.venv/bin/python scripts/evaluate_java_flow.py \
  --manifest config/evaluation/high-star-java-projects.json \
  --output docs/java-flow-project-results.json

.venv/bin/python scripts/evaluate_java_flow.py \
  --source-root /path/to/BenchmarkJava/src/main/java/org/owasp/benchmark/testcode \
  --output /tmp/java-flow-benchmark.json

.venv/bin/python scripts/score_owasp_benchmark.py \
  --expected /path/to/BenchmarkJava/expectedresults-1.2.csv \
  --results /path/to/static-results.json \
  --flow-results /tmp/java-flow-benchmark.json \
  --output docs/semgrep-owasp-benchmark-results.json
```
