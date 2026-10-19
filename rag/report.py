"""汇总所有评测结果 → eval/summary.json（README 和演示页都读这一份）。

    python rag/report.py

包含：各实验组（测试集）主指标与自助法置信区间、分类别结果、实验组之间的配对 McNemar 检验、
核验器自检（安全性 / 上限）、数据污染对比（原版 vs 混淆版，开发集）、攻击实验结果。
"""

from __future__ import annotations

import json
import math
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from metrics import bootstrap, outcome, summarize  # noqa: E402
from score import union_outcome  # noqa: E402

R = Path("eval/results")


def load(p: Path) -> list[dict]:
    return [json.loads(l) for l in open(p, encoding="utf-8")] if p.exists() else []


def mcnemar(a: list[dict], b: list[dict], key) -> dict:
    """只在误报用例上比较「是否被排除」：b 排除而 a 没排除的个数 vs 反过来的个数（精确二项检验）。"""
    ka = {r["name"]: key(r) == "dismissed" for r in a if not r["label"]}
    kb = {r["name"]: key(r) == "dismissed" for r in b if not r["label"]}
    n01 = sum(1 for k in ka if not ka[k] and kb.get(k))
    n10 = sum(1 for k in ka if ka[k] and not kb.get(k))
    n = n01 + n10
    p = min(1.0, 2 * sum(math.comb(n, i) for i in range(0, min(n01, n10) + 1)) / 2**n) if n else 1.0
    return {"b_only": n01, "a_only": n10, "p_value": round(p, 4)}


def arm_block(rows: list[dict]) -> dict:
    out = {}
    for name, key in (("unverified", lambda r: outcome(r)), ("verified", union_outcome)):
        s = summarize(rows, key)
        lo, hi = bootstrap(rows, "fp_dismiss_rate", key, n=1000)
        s["fp_dismiss_ci"] = [round(lo, 4), round(hi, 4)]
        s["by_category"] = {}
        for cat in sorted({r["category"] for r in rows}):
            c = summarize([r for r in rows if r["category"] == cat], key)
            s["by_category"][cat] = {k: c[k] for k in ("true", "false", "fp_dismissed", "tp_dismissed")}
        out[name] = {k: (round(v, 4) if isinstance(v, float) else v) for k, v in s.items()}
    lat = [r.get("latency_s", 0) for r in rows]
    toks = [r.get("usage", {}).get("completion_tokens", 0) for r in rows]
    out["avg_latency_s"] = round(sum(lat) / max(len(lat), 1), 1)
    out["avg_output_tokens"] = round(sum(toks) / max(len(toks), 1))
    return out


def main() -> None:
    summary = {"dataset": "OWASP Benchmark v1.2（cmdi / sqli / pathtraver / xss，混淆版代码）", "model": "Qwen3-8B（FP8，vLLM，思考模式）", "split": {}}
    cases = [json.loads(l) for l in open("eval/cases.jsonl", encoding="utf-8")]
    for sp in ("dev", "test"):
        cs = [c for c in cases if c["split"] == sp]
        summary["split"][sp] = {"n": len(cs), "true": sum(c["label"] for c in cs), "false": sum(not c["label"] for c in cs)}

    arms = {}
    for arm in ("bare", "knowledge", "random_kb", "context"):
        rows = load(R / f"qwen3-8b_{arm}_obf_test_think.verified.jsonl")
        if rows:
            arms[arm] = arm_block(rows)
    summary["test_arms"] = arms
    summary["paired_tests"] = {}
    base = load(R / "qwen3-8b_bare_obf_test_think.verified.jsonl")
    for arm in ("knowledge", "random_kb", "context"):
        other = load(R / f"qwen3-8b_{arm}_obf_test_think.verified.jsonl")
        if base and other:
            summary["paired_tests"][f"bare_vs_{arm}"] = mcnemar(base, other, union_outcome)
    if base:
        summary["analysis_only_test"] = summarize([{**r, "verdict": "false_positive" if r.get("analysis_ok") else "uncertain"} for r in base])

    st = json.load(open("eval/verifier_selftest.json", encoding="utf-8"))
    test_names = {c["name"] for c in cases if c["split"] == "test"}
    stt = [r for r in st if r["name"] in test_names]
    summary["verifier_selftest"] = {
        "true_cases": sum(r["label"] for r in st),
        "true_with_any_passing_claim": sum(1 for r in st if r["label"] and r["passed"]),
        "false_cases": sum(not r["label"] for r in st),
        "false_with_passing_claim_all": sum(1 for r in st if not r["label"] and r["passed"]),
        "false_with_passing_claim_test": sum(1 for r in stt if not r["label"] and r["passed"]),
        "false_cases_test": sum(not r["label"] for r in stt),
        "no_sink_found": sum(1 for r in st if r["sinks"] == 0),
    }

    v1 = R / "v1"
    contam = {}
    for variant in ("orig", "obf"):
        rows = load(v1 / f"qwen3-8b_bare_{variant}_dev.jsonl")
        if rows:
            s = summarize(rows)
            contam[variant] = {"fp_dismissed": s["fp_dismissed"], "false": s["false"], "tp_dismissed": s["tp_dismissed"], "true": s["true"]}
    summary["contamination_dev_v1"] = contam

    att = {}
    r1 = load(Path("eval/attacks_v1/attack_adaptive_run1.jsonl"))
    if r1:
        att["adaptive_run1"] = {"n": len(r1), "rounds": 10, "llm_fooled": sum(r["llm_success_round"] is not None for r in r1),
                                "pipeline_fooled": sum(r["pipeline_success_round"] is not None for r in r1),
                                "note": "第一次运行：攻击模型把 bar 改名成已存在的 param，生成了编译不通过的代码，核验器误判为安全。已修复（禁止撞名改名；核验器拒绝含重复声明的代码），见第二次运行"}
    for name in ("flips", "inject", "poison", "adaptive"):
        rows = load(Path(f"eval/attack_{name}.jsonl"))
        if not rows:
            continue
        if name == "flips":
            att[name] = {"pairs": len(rows),
                         "llm_orig_fp": sum(r["orig_verdict"] == "false_positive" for r in rows),
                         "llm_flip_still_fp": sum(r["flip_verdict"] == "false_positive" for r in rows),
                         "llm_both_correct": sum(r["orig_verdict"] == "false_positive" and r["flip_verdict"] == "real" for r in rows),
                         "pipeline_orig_dismissed": sum(r["orig_pipeline"] for r in rows),
                         "pipeline_flip_dismissed": sum(r["flip_pipeline"] for r in rows)}
        elif name == "inject":
            att[name] = {k: {"n": sum(1 for r in rows if k in r), "llm_fooled": sum(r[k]["llm_fp"] for r in rows if k in r),
                             "pipeline_fooled": sum(r[k]["pipeline"] for r in rows if k in r)} for k in ("control", "comment", "string", "identifier")}
        elif name == "poison":
            ks = [k for k in rows[0] if k.startswith("k")]
            att[name] = {k: {"n": len(rows), "llm_fooled": sum(r[k]["llm_fp"] for r in rows), "pipeline_fooled": sum(r[k]["pipeline"] for r in rows)} for k in ks}
        else:
            att[name] = {"n": len(rows), "rounds": 10, "llm_fooled": sum(r["llm_success_round"] is not None for r in rows),
                         "pipeline_fooled": sum(r["pipeline_success_round"] is not None for r in rows)}
    summary["attacks"] = att
    hits = Path("eval/scanner_hits_summary.json")
    if hits.exists():
        summary["scanner_coverage"] = json.loads(hits.read_text(encoding="utf-8"))
    Path("eval/summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=1), encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=False, indent=1)[:4000])


if __name__ == "__main__":
    main()
