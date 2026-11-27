# Benchmark results

Date: 2026-11-27. Corpus: 16 malicious and 6 benign cases.
Reproduce: `python -m bench.run --scanner self --scanner skillspector --date 2026-11-27`

Scanners: self 0.2.0.dev0 (ruleset 0); skillspector SkillSpector v2.13.7.
Model stages are off for every scanner in this table.

| Scanner | Static-scope cases caught | Benign passed | Benign blocked | Median seconds |
| --- | --- | --- | --- | --- |
| self | 2/13 | 0/6 | 5 | 0.0 |
| skillspector | 5/13 | 5/6 | 0 | 3.0 |

Per class (BLOCK / REVIEW / PASS of total; * = outside static scope):

| Class | self | skillspector |
| --- | --- | --- |
| download-run | 0 / 3 / 0 of 3 | 1 / 1 / 1 of 3 |
| dynamic-exec | 0 / 0 / 1 of 1 | 1 / 0 / 0 of 1 |
| hidden-instruction | 0 / 0 / 2 of 2 | 1 / 1 / 0 of 2 |
| instruction-override | 0 / 0 / 1 of 1 | 0 / 1 / 0 of 1 |
| non-english-injection * | 0 / 0 / 1 of 1 | 0 / 0 / 1 of 1 |
| odd-file | 2 / 0 / 0 of 2 | 1 / 1 / 0 of 2 |
| paraphrased-injection * | 0 / 0 / 1 of 1 | 0 / 0 / 1 of 1 |
| reverse-shell | 0 / 0 / 1 of 1 | 1 / 0 / 0 of 1 |
| secret-exfil | 0 / 2 / 0 of 2 | 0 / 1 / 1 of 2 |
| unprompted-exec | 0 / 1 / 0 of 1 | 0 / 1 / 0 of 1 |
| weak-signal * | 0 / 0 / 1 of 1 | 1 / 0 / 0 of 1 |

A case counts as caught when the verdict is at least as strict as the case expects.
