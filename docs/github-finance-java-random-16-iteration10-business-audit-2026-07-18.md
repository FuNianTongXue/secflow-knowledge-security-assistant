# GitHub 随机金融 Java 项目业务漏洞扫描评估（iteration10）

生成时间：2026-07-18

## 样本与口径

- 随机候选项目：16 个 GitHub 金融/支付/银行/钱包/转账相关开源项目。
- 有可分析 Java 生产源码的项目：11 个。
- 本轮实际扫描 Java 文件：718 个。
- 总唯一告警：74 个。
- 金融业务类告警：62 个。
- 普通 GitHub 项目没有 OWASP Benchmark 这种官方 ground truth，因此这里不宣称真实召回率；本报告使用“人工核验确认率 / 疑似误报率”衡量金融业务规则质量。

## 本轮最终扫描结果

| 规则 | 命中数 | 说明 |
| --- | ---: | --- |
| `finance.money-float` | 27 | 金额、余额、利息、汇率等使用 `double/float/Double/Float`。 |
| `finance.money-operation-without-transaction` | 21 | 扣款、入账、订单/流水保存缺少事务边界。 |
| `finance.missing-idempotency-key` | 7 | 支付、转账、充值、提现等资金接口缺少幂等键或请求去重。 |
| `finance.bigdecimal-from-double-literal` | 6 | `new BigDecimal(0.01)` 等 double 字面量构造。 |
| `finance.bigdecimal-from-double-variable` | 1 | `new BigDecimal(Double total)` 等 double 变量构造。 |

## 项目级命中

| 项目 | Java 文件 | 金融业务告警 | 主要风险 |
| --- | ---: | ---: | --- |
| `myNameIssls/payment-system` | 324 | 6 | 分金额换算使用 `new BigDecimal(0.01)`。 |
| `grzegorz103/virtual-bank-system` | 174 | 11 | 汇率/余额使用 `float`，授信入账缺事务边界。 |
| `Nuralam51/Spring-Boot-Payment-Gateway` | 6 | 3 | 支付接口缺幂等，金额使用 `double`，`BigDecimal(Double)`。 |
| `Kavindulakmal/MicroServices-SpringBoot` | 20 | 4 | 支付创建/更新缺幂等与事务边界。 |
| `hidemon/BankSystem` | 41 | 11 | 贷款/存款/信用卡利息使用 `double`。 |
| `kishan169/PaymentWalletApplicationAPI` | 56 | 27 | 账单支付、钱包转账、钱包与银行卡互转缺幂等与事务边界，金额字段使用 `double/Double`。 |

## 人工核验结论

按 finding 级别抽样核验，62 个金融业务告警中：

- 高置信真阳性 / 合理风险候选：约 60 个。
- 疑似误报或低价值噪声：约 2 个。
- 人工确认率：约 96.8%。
- 疑似误报率：约 3.2%。

主要疑似误报来自 `finance.money-float` 对只用于展示余额的局部变量 `Double balance` 的报告；这类变量不直接参与资金计算或持久化，后续可进一步收紧为“字段、实体属性、DTO 入参、计算表达式优先”，降低展示层噪声。

## 本轮根据扫描结果完成的优化

1. 降低误报：
   - 移除了事务边界规则中宽泛的 `setAmount(...)` / `setMoney(...)` 命中，避免把第三方支付 SDK 对象构造误判为资金持久化更新。
   - 过滤顶层 `example/src/main/**`、`sample/src/main/**` 等示例模块，避免示例代码污染生产审计结果。
   - 去掉 `bank`、`bill`、`wallet` 这类单独静态名词触发，避免把绑卡、解绑银行卡、普通账单资料维护误判成资金交易。

2. 降低漏报：
   - 新增 `BigDecimal(double/float 变量)` 资金精度规则，补出 `new BigDecimal(total)` 类风险。
   - 幂等规则从 POST 扩展到 PUT/PATCH 资金接口，补出 `PUT /fundtran`、`PUT /deposite`、`POST /addMoney` 等重复请求风险。
   - 资金事务边界规则补充 `fund/money` 业务方法名，覆盖银行账户到钱包、钱包到银行等互转场景。

3. 回归保护：
   - 新增回归测试覆盖资金 PUT 幂等、`addMoney` 事务边界、PayPal SDK `setAmount` 非持久化误报、绑卡/账单资料维护非资金动作等场景。

## OWASP Benchmark 回归

金融业务规则优化后，OWASP Benchmark 综合分未下降：

| 分区 | Precision | Recall | F1 |
| --- | ---: | ---: | ---: |
| 全量 | 0.764996 | 0.766078 | 0.765537 |
| Holdout | 0.734015 | 0.743523 | 0.738738 |

对应结果文件：

- `docs/apache100-owasp-engine-iteration10-finance-balanced-results.json`
- `docs/apache100-owasp-engine-iteration10-finance-balanced-holdout-results.json`

## 后续建议

1. 将资金事务边界报告从“每个 sink 一条”增加为“按方法聚合的一条业务风险卡片”，降低报告噪声。
2. 对 `finance.money-float` 增加上下文权重：实体字段、DTO 字段、请求参数、计算表达式高优先级；展示层临时变量低优先级或不报。
3. 增加跨文件资金流分析：Controller → Service → Repository 的路径上，如果 Controller 已命中幂等缺失，同时 Service 命中事务边界，报告中心应合并成一条“资金请求完整链路风险”。
4. 继续用随机真实项目做闭环：每轮记录误报/漏报样本，把规则改动先写测试，再跑 OWASP + 金融样本回归。
