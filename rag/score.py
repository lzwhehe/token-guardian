"""给研判结果加上核验器结论，并汇报「不核验」和「核验后」两种口径的指标。

    python rag/score.py eval/results/qwen3-8b_bare_obf_dev.jsonl [...]
    python rag/score.py --analysis-only --split dev      # 不用大模型的基线：只靠保守污点分析

核验结果写回 eval/results/<同名>.verified.jsonl。
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from metrics import bootstrap, outcome, summarize  # noqa: E402
from verifier import verify  # noqa: E402
from verifier_selftest import load_helpers  # noqa: E402

HELPERS = load_helpers(str(Path(__file__).resolve().parent.parent.parent / "data/BenchmarkJava/src/main/java/org/owasp/benchmark/helpers"))


_AO: dict = {}


def analysis_ok(c: dict) -> bool:
    """不用大模型的保守分析能否直接证明安全（结果缓存）。"""
    if c["name"] not in _AO:
        code = c["code_obf"]
        lines = code.splitlines()
        first = next((i for i, l in enumerate(lines, 1) if l.strip().startswith("public void doPost")), 1)
        _AO[c["name"]] = verify(code, c["cwe"], {"type": "no_taint", "line": first, "expr": lines[first - 1].strip()}, HELPERS).ok
    return _AO[c["name"]]


def union_outcome(r: dict) -> str:
    """最终口径：程序分析直接证明安全，或大模型提出的任一理由核验通过 → 排除；其余按大模型结论保留或复核。
    v2 起不再要求 verdict = false_positive：理由一旦被核验器证明成立，告警就是安全的。"""
    if r.get("analysis_ok") or r.get("verify_ok"):
        return "dismissed"
    return "kept" if r["verdict"] == "real" else "review"


def line(name: str, rows: list[dict], key) -> str:
    s = summarize(rows, key)
    lo, hi = bootstrap(rows, "fp_dismiss_rate", key, n=1000)
    return (f"{name:46s} 误报排除 {s['fp_dismissed']:3d}/{s['false']:3d} ({s['fp_dismiss_rate']:5.1%} [{lo:4.1%},{hi:4.1%}])"
            f"  真漏洞被排除 {s['tp_dismissed']:2d}/{s['true']:3d}  复核 {s['review_rate']:5.1%}")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("files", nargs="*")
    ap.add_argument("--cases", default="eval/cases.jsonl")
    ap.add_argument("--analysis-only", action="store_true")
    ap.add_argument("--split", default="dev")
    a = ap.parse_args()
    cases = {c["name"]: c for c in (json.loads(l) for l in open(a.cases, encoding="utf-8"))}

    if a.analysis_only:
        rows = []
        for c in cases.values():
            if a.split != "all" and c["split"] != a.split:
                continue
            code = c["code_obf"]
            first = next((i for i, l in enumerate(code.split("\n"), 1) if l.strip().startswith("public void doPost")), 1)
            r = verify(code, c["cwe"], {"type": "no_taint", "line": first, "expr": code.split("\n")[first - 1].strip()}, HELPERS)
            rows.append({"name": c["name"], "category": c["category"], "label": c["label"], "verdict": "false_positive" if r.ok else "uncertain", "verify_ok": r.ok})
        print(line(f"analysis_only_{a.split}", rows, lambda r: outcome(r)))
        return

    for f in a.files:
        rows = [json.loads(l) for l in open(f, encoding="utf-8")]
        for r in rows:
            c = cases[r["name"]]
            code = c["code_obf"] if r.get("variant", "obf") == "obf" else c["code"]
            claims = r.get("claims") or ([r["claim"]] if r.get("claim") and r["verdict"] == "false_positive" else [])
            r["verify_ok"], r["verify_reason"] = False, "没有理由"
            # 模型常常指对了行、却标错了理由类型：核验器以模型指出的行和原文为准，自己判断这一行
            # 属于哪种理由。这样仍然安全 —— 自检里对真漏洞的每一行、每种类型都试过，没有一个能通过。
            types = ("dead_branch", "key_mismatch", "sanitizer", "overwritten", "param_query", "no_taint")
            for cl in claims[:3]:
                cl = cl or {}
                for t in (cl.get("type"), *[x for x in types if x != cl.get("type")]):
                    v = verify(code, c["cwe"], {**cl, "type": t}, HELPERS)
                    r["verify_ok"], r["verify_reason"] = v.ok, v.reason
                    if v.ok:
                        r["verified_claim"] = {**cl, "type": t, "type_corrected": t != cl.get("type")}
                        break
                if r["verify_ok"]:
                    break
            r["analysis_ok"] = analysis_ok(cases[r["name"]])
        out = Path(f).with_suffix(".verified.jsonl")
        out.write_text("".join(json.dumps(r, ensure_ascii=False) + "\n" for r in rows), encoding="utf-8")
        stem = Path(f).stem
        print(line(stem + "  [不核验]", rows, lambda r: outcome(r)))
        print(line(stem + "  [核验后]", rows, lambda r: outcome(r, r.get("verify_ok", False))))
        print(line(stem + "  [程序分析∪核验后]", rows, union_outcome))


if __name__ == "__main__":
    main()
