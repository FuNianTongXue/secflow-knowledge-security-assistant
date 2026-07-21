# GitHub 金融/证券/交易 Java 项目幂等性扫描评估

- 生成时间：2026-07-18T16:12:48.744462+00:00
- 项目数：6 请求 / 6 完成
- 上传路径：`POST /api/ask`，按 mac 客户端目录拖入规则限制 300 文件、单文件 120k 字符、总 600 万字符
- 银标候选幂等性问题：4
- 引擎幂等性命中：8
- TP / FP / FN：4 / 4 / 0
- Precision：0.5
- Recall：1.0
- 误报率 proxy：0.5
- 漏报率 proxy：0.0

说明：真实 GitHub 项目没有维护方提供的逐行标准答案；这里的 FP/FN 是基于可复核银标规则的 proxy，不能等同于最终人工审计结论。

## 项目明细 Top 50

| 项目 | 状态 | Java | 上传文件 | 银标候选 | 引擎命中 | TP | FP | FN |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| shrestha-bishal/BankoneerCompleteBankingSystemCore | completed | 60 | 95 | 0 | 0 | 0 | 0 | 0 |
| tradingticket/JavaApi | completed | 75 | 77 | 0 | 0 | 0 | 0 | 0 |
| exchange-core/exchange-core | completed | 149 | 150 | 0 | 0 | 0 | 0 | 0 |
| quickfix-j/quickfixj | completed | 422 | 300 | 0 | 0 | 0 | 0 | 0 |
| Aniketchavhan1307/ChainX-Treading-Application | completed | 86 | 87 | 4 | 8 | 4 | 4 | 0 |
| imbix/bixcoin | completed | 31 | 32 | 0 | 0 | 0 | 0 | 0 |
