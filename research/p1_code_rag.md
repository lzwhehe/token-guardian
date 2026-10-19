# P1 research: RAG for SAST triage and fix suggestions in repo-vuln-scanner

Date: 2026-10-20. Scope: web research plus light verification. "Verified" means I checked the number myself (GitHub API, raw file, or primary page). "Vendor" means a self-reported marketing claim. "Unverified" means it came from a secondary summary only.

## 0. Starting point (from reading the code)

- `server/rules/vulnerabilityRules.js` holds about 12 regex rules. Each carries a `cwe` value: CWE-78, 89, 22, 918, 79, 502, 942, 1321, 94.
- `server/aiAnalysis.js` takes up to 8 high-risk file groups. For each it sends `findings[].context` plus an 80-line `codeEvidence` window to OpenAI or DeepSeek. The window is embedded with `JSON.stringify` inside the user message. The output is a strict JSON schema with fields such as `exploitability` and `falsePositiveSignals`.
- Nothing marks the code as untrusted data. Nothing stops the model from downgrading a finding because of a comment in the code. No knowledge is retrieved. Because each rule already has a CWE id, retrieval can use that CWE as an exact-match key, which makes it simple and dependable.

## 1. How industry does it

| Product | What the LLM is given or retrieves | Reported numbers |
|---|---|---|
| **GitHub Copilot Autofix** (CodeQL) | The SARIF alert; code snippets around the source, the sink and each flow-path step; the first ~10 lines of each involved file; **the CodeQL query help text** (rule docs). Fixes are tested in a harness on 2,300+ alerts: apply the fix, re-run the scan, check for new alerts, syntax errors and test changes. [docs.github.com responsible-use, fetched 2026-10-20](https://docs.github.com/en/code-security/responsible-use/responsible-use-autofix-code-scanning) | Vendor: fixes 3x faster overall, 7x for XSS, 12x for SQLi (beta data, [changelog 2024-08-14](https://github.blog/changelog/2024-08-14-copilot-autofix-for-codeql-code-scanning-alerts-is-now-generally-available/)). Vendor: "more than two-thirds" fixed with little or no editing ([TechTarget, 2024](https://www.techtarget.com/cybersecurity/news/366603045/GitHub-Copilot-Autofix-tackles-vulnerabilities-with-AI)). No acceptance rate is published. |
| **Semgrep Assistant + Memories** | Past triage decisions and developer feedback, stored as "memories" scoped by project, rule or vuln class, combined with "prompting and retrieval systems". The reasoning text cites the memory it used. [Semgrep blog 2025-06-12](https://semgrep.dev/blog/2025/making-zero-false-positive-sast-a-reality-with-ai-powered-memory) | Vendor: without memories it auto-filters about 20% of findings, with 95–96% user agreement. With memories, one rule went from 18 to 588 FPs filtered, and one customer saw 2.8x more FPs detected. ~60% of triage handled ([Semgrep 2025](https://semgrep.dev/blog/2025/semgrep-is-confidently-handling-60-of-all-triage-for-users-without-reducing-coverage)). |
| **Snyk DeepCode AI Fix** | Static-analysis "CodeReduce" trims the program down to the lines relevant to the fix before the LLM sees it. Fixes are checked with symbolic rules: the code must parse, the issue must be gone, and no new issue may appear. [arXiv 2402.13291, 2024-02](https://arxiv.org/abs/2402.13291); [Snyk blog](https://snyk.io/blog/deepcode-ai-vulnerability-autofixing) | Unverified (secondary summary): the Mixtral-based model removed >80% of defects and exactly matched the human fix in 10–50% of cases. |
| **Google "AI-powered patching"** | Sanitizer findings plus code, sent to Gemini; humans review each patch. [research.google, 2024-01](https://research.google/pubs/ai-powered-patching-the-future-of-automated-vulnerability-fixes/) | 15% of sanitizer bugs were fixed with an approved patch (C/C++, Java, Go). |
| **Amazon CodeGuru Security** | Support ended 2025-11-20; users were moved to Amazon Q Developer code review and Inspector. [AWS docs](https://docs.aws.amazon.com/it_it/codeguru/latest/security-ug/end-of-support.html) | Unverified: whether Q Developer generates SAST autofixes. |
| **Endor Labs AI SAST** | Several agents with tools for parsing, dataflow tracing and multi-pass reasoning. [Endor blog](https://www.endorlabs.com/learn/introducing-ai-sast-that-thinks-like-a-security-engineer) | Vendor: "up to 95%" fewer FPs, 92% on average ([IT Brief](https://itbrief.co.uk/story/endor-labs-unveils-ai-sast-tool-to-cut-false-positives-by-95)). |
| **ZeroPath** | An AI review of every candidate finding. [ZeroPath docs](https://zeropath.com/docs/scanning/sast-overview) | Vendor, and the figures conflict: "up to 75%" (docs), 85% (YC page), 92% (solutions page). |
| **Corgea** | (none found) | Unverified: "<5% FP rate", from a third-party directory only. |
| **Chinese vendors** (悬镜 灵脉AI, 奇安信, 开源网安) | (none found) | No primary FP data found. A CSDN article repeats vendor claims such as "AI 漏洞验证减少审计时间 90%" without sources. Treat as unverified. |

Industrial evidence with a real evaluation: a Tencent study ([arXiv 2601.18844, 2026-01-26](https://arxiv.org/abs/2601.18844)) used **433 real alarms (328 FP / 105 TP)**. Hybrid LLM + static-analysis methods removed 94–98% of FPs while keeping recall high, at $0.001–$0.12 and 2–110 s per alarm. Manual review takes 10–20 min per alarm.

**What the tools retrieve, in summary:** (1) the rule's own documentation (Copilot), (2) code context chosen by program analysis (Copilot flow path, Snyk CodeReduce), and (3) past human triage decisions (Semgrep). None of them publicly retrieves "similar CVE fixes" for triage. That approach shows up in research (Vul-RAG). The fixes are checked by re-running the deterministic scanner and tests, not by the LLM.

## 2. Research findings

- **Vul-RAG** ([arXiv 2406.11147, 2024](https://arxiv.org/abs/2406.11147)). It distils CVE + fix pairs into *knowledge* records (functional semantics, root cause, fix pattern) and retrieves them with BM25. On PairVul, pairwise accuracy rose by 16–24%. *Knowledge-level* RAG beat *code-level* RAG by 16–27%. In a user study, knowledge text raised human accuracy from 0.60 to 0.77. **Caveat:** a 2026 replication with open-weight models ([arXiv 2606.04739, 2026-06-03](https://arxiv.org/abs/2606.04739)) reproduced the results but found a **plateau of about 0.30 pairwise accuracy**, even with newer models. Expect modest gains from a local 7–8B model. This fits our earlier Probewise result, where 7–8B models judging directly missed 31–54%.
- **ZeroFalse** ([arXiv 2510.02534, 2025-10](https://arxiv.org/abs/2510.02534)). It feeds analyzer alerts to the LLM with flow traces and **CWE-specific context**, and reached F1 0.912 on OWASP Benchmark and 0.955 on OpenVuln. CWE-specialised prompts beat generic prompts, and reasoning models gave the best balance between precision and recall.
- **LLM4FPM** ([arXiv 2411.03079, 2024-11](https://arxiv.org/abs/2411.03079)). It extracts precise context with a CPG slicer and a file-reference graph. Results: F1 >99% on Juliet (synthetic, easy), 86% accuracy on D2A, about $0.384 per warning with an open-source LLM. Lesson: getting **precise context matters more than model size**.
- **IRIS** ([ICLR 2025 / arXiv 2405.17238](https://arxiv.org/abs/2405.17238)). The LLM infers taint sources and sinks for CodeQL and then filters alerts using context. On CWE-Bench-Java, CodeQL found 27/120 and IRIS + GPT-4 found 55. False discovery rate was about 5 pp lower in the final version; v1 claimed 69 detections and an 80% FP cut, which was later revised.
- **LLMxCPG** ([USENIX Sec 2025](https://www.usenix.org/conference/usenixsecurity25/presentation/lekssays)). CPG slices shrink the code by 68–91% and F1 improves by 15–40% over baselines. On a post-cutoff 2025 dataset F1 is 0.617, which shows these tasks are still hard.
- **PrimeVul** ([arXiv 2403.18624, 2024](https://arxiv.org/abs/2403.18624)). A 7B model scored 68% F1 on BigVul but **3.09% F1 on PrimeVul**. GPT-3.5/4 were close to random on paired vulnerable/fixed functions. Lesson: open-ended "is this function vulnerable?" is unreliable. Judging *a specific SAST finding* with context and rule knowledge works better, as ZeroFalse and the Tencent study show.

**What helped:** precise slicing or flow context; CWE-specific knowledge; hybrid static + LLM decisions; reasoning models.
**What did not help:** whole-function "vuln or not" classification; code-level nearest-neighbour RAG compared with knowledge-level RAG; larger models alone (the Vul-RAG replication plateau).
**Metrics used:** precision, recall and F1 on TP/FP labels; FP-reduction rate at a fixed recall; pairwise accuracy on vulnerable/fixed pairs; for fixes, alert cleared + no new alert + tests pass (Copilot) and pass@k (Snyk).

## 3. Labelled datasets (licenses checked with the GitHub API on 2026-10-20 unless noted)

| Dataset | Lang | Labels | License | Size |
|---|---|---|---|---|
| **OWASP Benchmark v1.2** | Java | `expectedresults-1.2.csv`: **2,740 cases, 1,415 true / 1,325 false, 11 categories, CWE id** (verified from the raw CSV) | GPL-2.0 | Repo ~76 MB |
| **CWE-Bench-Java** (IRIS) | Java | 120 CVEs with buggy and fixed versions plus fixed-function info; 4 CWEs (22, 78, 79, 94), all of which our rules cover | MIT | Seeds are small; full projects are fetched by script (large) |
| **Vul4J** | Java | Reproducible vulns with PoV tests; vulnerable and fixed versions | GPL-3.0 | Repo ~2.6 GB |
| **SecBench.js** | JavaScript (npm) | 600 vulns with exploits and oracles; folders for command-injection, code-injection, path-traversal, etc. ([ICSE 2023](https://github.com/cristianstaicu/SecBench.js)) | **No license file** (API returns null). Fine for local evaluation; do not redistribute | ~6 MB |
| **OWASP NodeGoat** | Node.js | A realistic vulnerable app; no ground-truth file | Apache-2.0 | ~9 MB |
| **OWASP Juice Shop** | TS/Node | `data/static/codefixes/`: **161 files of candidate fixes, with the correct one marked `_correct`** plus `info.yml` (verified). Useful for scoring fix suggestions | MIT | Repo ~320 MB |
| **CVEfixes** | Multi-language | Vulnerable and fixed commits, CWE, CVE | Code MIT, **data CC BY 4.0** | 12.7 GB zip (v1.0.8, [Zenodo 2024-07](https://zenodo.org/records/13118970)); 7,798 commits, 209 CWEs (v1.0.7) |
| **PrimeVul** | C/C++ | Paired vulnerable/fixed functions | MIT | Medium |
| **BigVul** (MSR'20) | C/C++ | Vulnerable/fixed functions, CVE summaries | MIT | Repo ~26 MB (data downloaded separately) |
| **DiverseVul** | C/C++ | 18,945 vulnerable / 349,437 functions, 150 CWEs (unverified, from a survey) | **No license file** | n/a |
| **SecurityEval** | Python | Prompts for evaluating code generation, not SAST findings | **No license file** | Small |
| **Juliet / SARD** | C/C++, Java, C# | Synthetic good/bad variants; Juliet 1.3 has 64,099 C/C++ and 28,886 Java cases ([NIST](https://samate.nist.gov/SARD/downloads/documents/releaseJuliet1.3Doc.txt)) | US-government work; public-domain status unverified | Large |
| JS-VulBench | JavaScript | 1,000 synthetic single-vuln files ([IEEE DataPort](https://ieee-dataport.org/documents/js-vulbench-javascript-vulnerability-benchmark-dataset-static-application-security)) | Unverified | Small |

### Recommended combination

**(a) Evaluating FP reduction by the LLM judge.** The test set should be *this scanner's own findings*, labelled TP or FP. That is what the judge actually sees.
1. **OWASP Benchmark v1.2 (primary, defensible, standard).** Run the scanner over it and join findings to `expectedresults` by test file and CWE. That yields real TP/FP labels on our own regex output. ZeroFalse also reports on it, so we have an external reference point. Report the OWASP Benchmark score (TPR − FPR) before and after the judge.
2. **CWE-Bench-Java plus SecBench.js (realistic, paired).** Scan both the vulnerable and the fixed version. A finding that persists in the fixed function is a likely FP. Report Vul-RAG-style pairwise accuracy. SecBench.js covers the Node.js CWE-78/94/22 rules.
3. **NodeGoat and Juice Shop (realism check).** Hand-label the 50–100 findings the scanner produces on them and report them separately.
4. **Juice Shop codefixes** for fix suggestions: given the vulnerable snippet, does our suggestion match, or is it judged equivalent to, the `_correct` variant?

**Headline metrics:** FP-reduction rate at **TP retention ≥ 95%**, the number of TPs wrongly dismissed (the costly error), and the injection attack success rate (Section 4).

**(b) Knowledge base.** CWE, CAPEC and OWASP Cheat Sheets for rule cards. **CVEfixes** filtered to JS/TS/Python/Java for vulnerable-to-fixed examples, distilled into Vul-RAG-style knowledge records.

**Avoiding test leakage:**
- Drop every CVE id, repo URL and package name that appears in CWE-Bench-Java, SecBench.js, NodeGoat, Juice Shop or OWASP Benchmark.
- Remove near-duplicates by normalised-code MinHash against all test functions.
- Add a time split: KB items before 2024 and paired test items after.
- Never index Benchmark or Juliet code into the KB.
- Store the KB manifest with SHA-256 hashes so the split can be audited.

## 4. Prompt injection via repository content

- **Comment attacks on LLM vulnerability detectors.** [Thornton, arXiv 2602.16741, 2026-02-18](https://arxiv.org/abs/2602.16741): 100 Python/JS/Java samples, 8 comment variants including authority spoofing, 8 models, 9,366 trials. Adversarial comments had **non-significant effects** (McNemar p > 0.21). The best defense was **cross-referencing with static analysis (96.9% detection, recovering 47% of misses)**. **Stripping comments hurt weaker models.** In contrast, **ALIBI** ([Wu & Nita-Rotaru, arXiv 2607.24964, 2026-07-27](https://arxiv.org/abs/2607.24964)) used *adaptive*, agent-generated comments asserting false safety conditions and reached **>90% ASR on 4 detectors, 100% on one**, across 125 null-deref cases. Prompt hardening gave limited protection. **Architectural isolation and stripping comments before detection** "substantially" improved robustness (no numbers in the abstract). In short, naive "this was reviewed" comments rarely work, but an adaptive attacker who can query the detector does. Our scanner is public, so assume the adaptive case.
- **Incidents.** CamoLeak (Copilot Chat): hidden PR comments took control of responses and leaked private code; disclosed 2025-10, fixed by disabling image rendering ([Legit Security](https://www.legitsecurity.com/blog/camoleak-critical-github-copilot-vulnerability-leaks-private-source-code)). "Comment and Control" (2026-04): PR titles and issue bodies hijacked Claude Code Security Review, Gemini CLI Action and the Copilot agent ([CSA note](https://labs.cloudsecurityalliance.org/research/csa-research-note-comment-control-github-prompt-injection-20/); details unverified). Hidden HTML in PRs steered review agents through the Azure DevOps MCP (2026-08, [CSA](https://labs.cloudsecurityalliance.org/research/csa-research-note-azure-devops-mcp-prompt-injection-20260801/); unverified).
- **KB poisoning.** PoisonedRAG ([USENIX Sec 2025](https://www.usenix.org/conference/usenixsecurity25/presentation/zou)): **5 injected texts per target query gave about 90% ASR** (97% on NQ in the arXiv version) in a KB of millions of texts. The defenses the authors evaluated were insufficient.
- **General defense.** Spotlighting/datamarking ([arXiv 2403.14720, 2024](https://arxiv.org/abs/2403.14720)) cut ASR from >50% to <3% on GPT-3.5 in a synthetic setup. Plain delimiters are easy to subvert.

### Defenses for this scanner
1. **The LLM can only demote a finding, and only with deterministic evidence.** For CWE-78/89/22/94, a "false positive" verdict counts only if it cites a sanitiser or safe idiom that a local check confirms. Examples: `execFile` called with an array of arguments; a parameterised query; `path.resolve` followed by a `startsWith` check. Otherwise the finding goes to "needs review", never "safe". This follows the Thornton result that static cross-referencing was the best defense.
2. **Judge twice: once on the original window, once on a comment- and string-stripped window** (parse with acorn/babel; mask string literals). If the verdict flips to safe *only* when comments are present, flag the finding as `comment-influenced` and keep it. This avoids Thornton's "stripping hurts" problem while still getting ALIBI's isolation benefit.
3. **Datamark the untrusted code** (Spotlighting) and put it in a separate, clearly labelled field. The system prompt says it is data. Keep the strict JSON schema with enums, which is already in place.
4. **Read-only KB.** Build it offline from pinned sources with hashes. **Never index scanned repositories.** Like Semgrep, "memories" should come only from *human-confirmed* triage, scoped per rule, stored separately and shown in the output.
5. **Red-team set.** Inject "security-reviewed / sanitized upstream" comments, README text and string literals into OWASP Benchmark *true* cases. Measure the flip rate (ASR) before and after each defense.

## 5. KB sources and licenses

| Source | License | Notes |
|---|---|---|
| CWE | MITRE terms of use: royalty-free for research and commercial use; **copies must reproduce MITRE's copyright notice and the license** ([cwe.mitre.org ToU, fetched 2026-10-20](https://cwe.mitre.org/about/termsofuse.html)) | Use the Description, Potential Mitigations, Demonstrative Examples and Observed Examples fields. |
| CAPEC | Same style of MITRE terms; keep the notice ([CAPEC ToU](https://capec.mitre.org/about/termsofuse.html)) | Attack context for the explanation only. |
| OWASP Cheat Sheet Series | **CC BY-SA 4.0** (verified via the GitHub API) | Attribute each chunk. Derivative KB text is share-alike, so keep the KB as a separate, attributed data file rather than mixing it into the code license. Best source for fix patterns (OS Command Injection Defense, SQL Injection Prevention, Node.js Security, SSRF, Deserialization). |
| NVD | US-government data, treated as public domain; do not imply NVD endorsement, and do not attribute modified content to NVD ([NVD ToU](https://nvd.nist.gov/developers/terms-of-use)) | CVE descriptions to link with CVEfixes examples. |
| CVEfixes | Data CC BY 4.0 | Attribute it. The code snippets inside come from upstream projects under their own licenses, so store short excerpts with links. |

## 6. Concrete plan

1. Build `kb/rule_cards/*.json`, one per CWE in `vulnerabilityRules.js`, with fields: CWE summary, mitigations, **known-safe idioms (FP patterns)**, fix template and source citations. Retrieve by exact CWE and rule id, then BM25 on the sink API name. No embeddings are needed for v1.
2. Add 200–500 Vul-RAG-style knowledge records distilled from CVEfixes JS/Python/Java, after the leakage filters above.
3. Update the judge prompt: rule card, top-3 knowledge records, and the datamarked code window. Output must include `citedKnowledgeIds[]`; drop any citation that is not in the retrieved set.
4. Fix suggestions: the LLM proposes a patch, the scanner re-runs on the patched window, the alert must clear with no new alerts, and the output links to the cheat-sheet sections it used (as in Copilot Autofix).
5. Evaluate in ablation order: no LLM → LLM with no RAG → + rule cards → + knowledge records → + defenses. Report each step on OWASP Benchmark, the paired sets and the injection set.
