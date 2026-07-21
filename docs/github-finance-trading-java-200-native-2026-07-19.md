# GitHub 金融/证券/交易 Java 项目幂等性扫描评估

- 生成时间：2026-07-19T02:42:52.721422+00:00
- 项目数：200 请求 / 200 完成
- 上传路径：`POST /api/ask`，按 mac 客户端目录拖入规则限制 300 文件、单文件 120k 字符、总 600 万字符
- 启发式复核候选：187
- 引擎幂等性命中：500
- 引擎资金逻辑总命中：1805
- 引擎与候选同位置匹配：160
- 仅引擎命中 / 仅候选：340 / 27

说明：真实 GitHub 项目没有维护方提供的逐行标准答案，因此本报告不计算或声称 Precision、Recall、FPR、FNR。候选一致性仅用于抽样复核，不是准确率。

## 项目明细 Top 50

| 项目 | 状态 | Java | 上传文件 | 复核候选 | 引擎命中 | 同位置 | 仅引擎 | 仅候选 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| shrestha-bishal/BankoneerCompleteBankingSystemCore | completed | 60 | 95 | 0 | 0 | 0 | 0 | 0 |
| tradingticket/JavaApi | completed | 75 | 77 | 0 | 0 | 0 | 0 | 0 |
| exchange-core/exchange-core | completed | 149 | 150 | 0 | 0 | 0 | 0 | 0 |
| quickfix-j/quickfixj | completed | 422 | 300 | 0 | 0 | 0 | 0 | 0 |
| Aniketchavhan1307/ChainX-Treading-Application | completed | 86 | 87 | 6 | 16 | 6 | 10 | 0 |
| imbix/bixcoin | completed | 31 | 32 | 0 | 0 | 0 | 0 | 0 |
| UlasT35/Bank-Management-System | completed | 42 | 42 | 0 | 0 | 0 | 0 | 0 |
| nikolatechie/trading-simulator | completed | 79 | 140 | 1 | 2 | 1 | 1 | 0 |
| hinokamikagura/crypto-wallet-engine | completed | 59 | 75 | 1 | 8 | 1 | 7 | 0 |
| annax3/PAYMENT-GURU | completed | 42 | 44 | 4 | 7 | 4 | 3 | 0 |
| frostishyper/Black_Shores_Bank | completed | 44 | 55 | 0 | 0 | 0 | 0 | 0 |
| nguemechieu/investpro | completed | 1223 | 300 | 0 | 0 | 0 | 0 | 0 |
| echenim/Financial-Inclusion-FieldAgent | completed | 44 | 44 | 0 | 0 | 0 | 0 | 0 |
| saifcores/afripay | completed | 89 | 100 | 8 | 9 | 6 | 3 | 2 |
| tayylorngo/CSE390-Final-Project-Paper-Trading-App | completed | 14 | 14 | 0 | 0 | 0 | 0 | 0 |
| chandansharma65914/worried-way-9596 | completed | 11 | 11 | 0 | 0 | 0 | 0 | 0 |
| Shubhtiwari29/Crypto-Treading-Platform---Backend | completed | 108 | 109 | 7 | 13 | 6 | 7 | 1 |
| LM10QUEMERABOBO/Trade-Shift-A-Financial-Portfolio-Management-Trading-Platform | completed | 39 | 60 | 1 | 4 | 1 | 3 | 0 |
| borishristovv/space-race-exchange | completed | 135 | 139 | 0 | 0 | 0 | 0 | 0 |
| tonnymuchui/Trading-Backend | completed | 110 | 111 | 7 | 13 | 6 | 7 | 1 |
| Vani-priyaa/OrderBookStimulator | completed | 1 | 1 | 0 | 0 | 0 | 0 | 0 |
| jammy928/CoinExchange_CryptoExchange_Java | completed | 878 | 300 | 13 | 24 | 13 | 11 | 0 |
| philipperemy/Order-Book-Matching-Engine | completed | 7 | 7 | 0 | 0 | 0 | 0 | 0 |
| sanzol-tech/ai-trader | completed | 284 | 293 | 0 | 0 | 0 | 0 | 0 |
| yildizmy/e-wallet | completed | 65 | 143 | 3 | 10 | 3 | 7 | 0 |
| medovarszki/ibkrfacade | completed | 23 | 24 | 1 | 2 | 1 | 1 | 0 |
| rehmanis/stocks-android | completed | 19 | 19 | 0 | 0 | 0 | 0 | 0 |
| davidgracemann/FlossPay | completed | 31 | 37 | 0 | 0 | 0 | 0 | 0 |
| epam/TimebaseCryptoConnectors | completed | 214 | 214 | 0 | 0 | 0 | 0 | 0 |
| epam/TimebaseOrderBook | completed | 92 | 92 | 0 | 0 | 0 | 0 | 0 |
| thiaguimcavalcanti/ta4j-strategies-factory | completed | 12 | 12 | 0 | 0 | 0 | 0 | 0 |
| ebinjoy999/Cryptocurrency-Trader | completed | 25 | 25 | 0 | 0 | 0 | 0 | 0 |
| Shubh00796/PayTrack-Financial_Transaction_Processor | completed | 100 | 101 | 2 | 5 | 2 | 3 | 0 |
| MikeMordec/StockMarketSimulator | completed | 13 | 13 | 0 | 0 | 0 | 0 | 0 |
| shivendra-somr/StockSage | completed | 21 | 21 | 0 | 0 | 0 | 0 | 0 |
| RavishekSingh/QuickPay_Payment_Wallet_App.github.io | completed | 52 | 54 | 3 | 9 | 3 | 6 | 0 |
| moksnow/Mixar | completed | 52 | 53 | 0 | 0 | 0 | 0 | 0 |
| AyushGupta3900/Matchbox | completed | 122 | 126 | 0 | 11 | 0 | 11 | 0 |
| CanduriFranklin/FinOpsBank | completed | 22 | 24 | 0 | 0 | 0 | 0 | 0 |
| PhathisaNdaliso/openex-crypto-exchange | completed | 41 | 58 | 1 | 8 | 1 | 7 | 0 |
| LewallenAE/JavaHFT | completed | 19 | 20 | 0 | 0 | 0 | 0 | 0 |
| fulbabu-t/Ui-project- | completed | 19 | 20 | 0 | 4 | 0 | 4 | 0 |
| Ale-Newport/Stock-Market-Simulator | completed | 18 | 19 | 0 | 0 | 0 | 0 | 0 |
| CANWIA00/ExchangeAPIv1 | completed | 60 | 61 | 1 | 3 | 1 | 2 | 0 |
| dariusz18/J.-POO-Morgan-Chase-Co-in-Java | completed | 45 | 45 | 0 | 0 | 0 | 0 | 0 |
| tlb-lemrabott/stock-exchange-platform | completed | 21 | 30 | 1 | 2 | 1 | 1 | 0 |
| sambacha/atlas-engine | completed | 126 | 134 | 4 | 4 | 4 | 0 | 0 |
| shruti-gavhane/Stock-Exachange-Maching-Engine | completed | 11 | 11 | 0 | 0 | 0 | 0 | 0 |
| piyushaanand/Trading-Backend | completed | 86 | 87 | 6 | 16 | 6 | 10 | 0 |
| andzia0520/stock_trading_platform | completed | 44 | 46 | 0 | 2 | 0 | 2 | 0 |
