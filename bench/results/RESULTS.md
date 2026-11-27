# Benchmark results

Date: 2026-11-27. Corpus: 53 malicious and 20 benign cases.
Reproduce: `python -m bench.run --scanner self --scanner skillspector --scanner cisco-skill-scanner --date 2026-11-27`

Scanners: self 0.9.0 (ruleset 9); skillspector SkillSpector v2.13.7; cisco-skill-scanner skill-scanner 2.3.2.
Model stages are off for every scanner in this table.
The Cisco corpus run returned one adapter error. The reported denominator includes that case.
Most cases were written by this project's authors while building its checks, so this project's own numbers on them are optimistic; the real-skill results are the fairer measure of false alarms.

| Scanner | Static-scope cases caught | Benign passed | Benign blocked | Median seconds |
| --- | --- | --- | --- | --- |
| self | 50/50 | 18/20 | 0 | 0.0 |
| skillspector | 11/49 | 15/20 | 1 | 4.16 |
| cisco-skill-scanner | 25/49 | 15/20 | 4 | 4.6 |

Per class (BLOCK / REVIEW / PASS of total; * = outside static scope):

| Class | self | skillspector | cisco-skill-scanner |
| --- | --- | --- | --- |
| download-run | 10 / 0 / 0 of 10 | 3 / 3 / 4 of 10 | 6 / 0 / 4 of 10 |
| dynamic-exec | 4 / 0 / 0 of 4 | 1 / 1 / 2 of 4 | 3 / 0 / 1 of 4 |
| hidden-instruction | 3 / 0 / 0 of 3 | 1 / 2 / 0 of 3 | 2 / 0 / 1 of 3 |
| install-extra | 2 / 0 / 0 of 2 | 0 / 0 / 2 of 2 | 1 / 0 / 1 of 2 |
| instruction-override | 4 / 0 / 0 of 4 | 0 / 1 / 3 of 4 | 1 / 0 / 3 of 4 |
| mismatch | 3 / 0 / 0 of 3 | 2 / 0 / 1 of 3 | 0 / 0 / 3 of 3 |
| non-english-injection * | 0 / 0 / 1 of 1 | 0 / 0 / 1 of 1 | 0 / 0 / 1 of 1 |
| odd-file | 3 / 0 / 0 of 3 | 1 / 2 / 0 of 3 | 0 / 1 / 2 of 3 |
| paraphrased-injection * | 1 / 0 / 0 of 1 | 0 / 0 / 1 of 1 | 0 / 0 / 1 of 1 |
| reverse-shell | 3 / 0 / 0 of 3 | 2 / 0 / 1 of 3 | 3 / 0 / 0 of 3 |
| reviewer-directed | 4 / 0 / 0 of 4 | 0 / 0 / 4 of 4 | 0 / 0 / 4 of 4 |
| secret-exfil | 9 / 0 / 0 of 9 | 1 / 6 / 2 of 9 | 9 / 0 / 0 of 9 |
| unprompted-exec | 5 / 0 / 0 of 5 | 0 / 3 / 1 of 4 | 0 / 0 / 4 of 4 |
| weak-signal * | 0 / 1 / 0 of 1 | 1 / 0 / 0 of 1 | 1 / 0 / 0 of 1 |

A case counts as caught when the verdict is at least as strict as the case expects.

Real skills (self): 2753 skills; PASS 2088, REVIEW 568, BLOCK 97; unjustified blocks 55 (2.0%); PASS rate 75.8%.
