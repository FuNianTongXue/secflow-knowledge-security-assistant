# Native Java Finance CFG/DFG Labeled Evaluation

Generated: 2026-07-19T01:49:00.397470+00:00

## Scope

Ground truth comes from manually separated positive and negative fixtures. Symbol-renamed variants are correlated regression cases and are not presented as independent GitHub ground truth.

## Metrics

| Set | N | TP | TN | FP | FN | Accuracy | Precision | Recall | FPR | FNR |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Independent templates | 33 | 17 | 16 | 0 | 0 | 100.000% | 100.000% | 100.000% | 0.000% | 0.000% |
| Expanded regression | 2112 | 1088 | 1024 | 0 | 0 | 100.000% | 100.000% | 100.000% | 0.000% | 0.000% |

Expanded threshold result: **PASS**

FPR 95% Wilson interval: `[0.0, 0.003737]`

FNR 95% Wilson interval: `[0.0, 0.003518]`

## Failures

No classification failures in the expanded regression set.

## Interpretation

Deterministic symbol/format variants exercise parser and data-flow stability but are correlated. Their rates are regression results, not a real-world prevalence or production accuracy guarantee.
