# P1 red-team review: RAG triage design (pre-build)

2026-10-20. Ordered by threat to the headline result.

## 1. The guard leaves the LLM nothing measurable to do, and the string-masked second pass discards real evidence
- **Evidence.** The checker confirms *idioms* (parameterised query, sanitizer call). Benchmark "false" cases are probably mostly *flow* tricks (the exact share has not been measured): constant-condition dead branches, overwrites, map/list lookups that return a constant. An idiom checker never confirms those, so they all land in "needs review". Wherever the checker *can* confirm a case, it can do so without the LLM, so the LLM's marginal value is ≈0 by construction. The second pass masks string literals, but collection-key FPs (`put("keyA",…)` / `get("keyB")`) and SQL structure depend on literal contents. Masking makes genuine FPs look vulnerable, so they get flagged "comment-influenced" and held. The listed idioms (execFile array, path.resolve+startsWith) are JS; the eval is Java.
- **Fix: a claim verifier instead of an idiom checker.** The LLM must output a typed, machine-checkable reason, for example `{type: dead_branch|overwritten|key_mismatch|sanitizer|param_query, lines, expr}`. A tree-sitter-java verifier then checks three things: (a) the cited expression appears verbatim in *code* (comments removed, never in a string); (b) the claim holds (constant-fold the condition, intraprocedural def-use for overwrite or key mismatch); (c) a sanitizer resolves to a library FQN that is **not defined inside the scanned repo**, which blocks a vendored fake `org.owasp.esapi`. A verified claim → dismiss. Anything else → review. Comment text can no longer move a verdict, and the LLM's job becomes *finding* the reason. Drop string masking and strip comments only. First measure on dev what share of FPs each claim type covers.

## 2. Knowledge retrieval does not address what makes Benchmark FPs false
- **Evidence.** CWE and cheat-sheet text cannot tell you whether `(7*42)-num > 200` holds. There are only 4 CWEs, so the exact-CWE rule card already contains nearly everything the retriever would return. Expect "+retrieval ≈ +rule card". Any small gain may come from a longer prompt rather than from knowledge.
- **Fix.** Add a **code-context arm**: the whole servlet plus inlined callee bodies (`doSomething`, Benchmark helper classes). This is RAG over the *scanned* repo, held in an untrusted "data" zone separate from the trusted KB. Also add a **length-matched random-KB control**. For knowledge that *can* help, build flow-pattern cards from Juliet Java good/bad variants (a different generator from Benchmark). Report the arms as: bare / +card / +code context / +retrieval / +random-KB / +verifier.

## 3. "Every case = one finding" says nothing about this scanner
- **Evidence.** I ran the regexes on 7 Benchmark-style sink lines and got **0/7 matches**. I wrote those lines from memory of the Benchmark code style, so confirm against the copy on the GPU server. Two causes: the rules target JS/Python APIs, and they match a single line. The CWE-78 rule also has a bug: the trailing `\b` after `\+` means `exec(cmd + bar)` never matches.
- **Fix.** Add Java sink rules: `exec`/`ProcessBuilder`, `execute*`/`prepare*`/`JDBCtemplate`, `new File`/`FileInputStream`/`Paths.get`, `getWriter().print|write|format`. Then the candidates really are scanner output, anchored at the sink line within the real 80-line window. Report coverage. Call the result a *triage component eval*. Do not compare it with ZeroFalse's F1, which used CodeQL flow traces.

## 4. Contamination check is weak; the split invites prompt overfitting
- **Evidence.** Renaming misses several tells: `@WebServlet("/cmdi-00/…")` (the category is in the URL), `org.owasp.benchmark.helpers.*`, and idioms such as `"This_should_always_happen"`. An 8B model will not have memorised 2,740 labels, but it may know the idioms. If original and obfuscated scores match, that shows nothing. Benchmark is built combinatorially (source × propagator × sink), so a random 80/20 split puts identical propagator templates in both dev and test, and any Benchmark-specific prompt hint carries straight over.
- **Fix.**
  - **Counterfactual label-flip pairs** (~100 per direction): a minimal semantic edit that flips the label, such as making the dead branch live or changing the map key. An accuracy drop on the flipped pairs indicates idiom matching.
  - **Group split** by normalised propagator template (MinHash with identifiers masked).
  - Write and **freeze** the prompt from generic principles, log every revision, and cap dev iterations.

## 5. Operating point and statistics are underspecified
- **Evidence.** The output has 3 classes (dismiss / review / keep), but "≥95% retention" does not say how "review" counts. 20% dev ≈ 155 TPs, so a 95% threshold rests on ~8 cases and realised test retention could be 92–98%. On test (~620 T / ~560 F) the FP-dismissal CI is ±4 pp overall and ±8–10 pp per category.
- **Fix.** Score = verdict-token logprob; set the threshold on dev only and report realised test retention with a bootstrap CI, without retuning. Also report the full curve and the Benchmark score (TPR − FPR). Compare arms with **paired** McNemar/bootstrap; differences under ~5 pp count as "not detectable". With the verifier, the hard numbers are *TPs dismissed* (target 0) and review rate. Greedy decoding, plus 3 seeds on the final arms.

## 6. Injection protocol needs concrete parameters
- **Fix.** Compute ASR only over TPs correctly kept *before* injection (stratified 100-TP subset). Test comment, string-literal and identifier placements (`sanitizedBar`, fake `isSafe()`) separately, keeping the equal-length benign control. **Adaptive attacker:** an attacker LLM (same or stronger) that knows the verifier, sees the final label *and* rationale, and gets 10 rounds per target; success = pipeline output "dismiss". Under the verifier the expected attack is code that only *looks* dead (opaque predicate, reflection). Report what gets through.

## 7. KB poisoning: decide who the attacker is
- **Evidence.** The KB is offline, read-only and built from pinned MITRE/OWASP sources, so nobody but the builder writes to it. With exact-CWE rule cards and a 4-CWE KB, a poison that contains the sink's tokens (`Runtime.getRuntime().exec`, `getHeader`, CWE-78) is retrieved almost every time, so the retrieval rate is trivially ~100%. The sha256 manifest audits leakage, not integrity, unless it is signed and checked at load time.
- **Fix.** Frame this as **defense in depth**: "even with a fully compromised KB, the verifier caps ASR at X". Use N ∈ {1, 3} PoisonedRAG-style texts (target tokens + a "safe because…" claim) on the same 100 TPs. The realistic write path is future triage "memories" (Semgrep-style) and upstream cheat-sheet PRs; document these and leave them out of scope.

## 8. Scope and compute (2–3 days)
- **H100 20 GB:** Qwen3-8B in bf16 (~16 GB) leaves almost no KV cache. Use FP8/AWQ, precompute KB embeddings, and run the reranker on CPU or skip it. Use thinking mode on one arm only.
- **Cut:** LangChain-vs-handwritten (pick one); the 50-query Recall@k labelling (relevance is ill-defined; the random-KB control replaces it); reranker/fusion ablations; CVEfixes; Qwen2.5-7B beyond the bare and final arms; Node integration until the end (a Python harness reads Benchmark directly).

## Must-fix before build
1. Replace the idiom checker with a typed claim verifier (code-only evidence, FQN not repo-defined). Strip comments only and do not mask strings.
2. Add a code-context arm and a length-matched random-KB control.
3. Add Java sink rules, fix the `\+\b` bug, and report real scanner coverage. Frame the result as a component eval.
4. Use counterfactual flip pairs, a template-group split, and a frozen, logged prompt.
5. Define 3-class metrics, a dev-only threshold with a bootstrap CI, and paired tests.
6. Pin the adaptive-attack budget and success criterion. Frame KB poisoning as defense in depth.
7. Quantise the LLM to fit in 20 GB and apply the §8 cuts.
