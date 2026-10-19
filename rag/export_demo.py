"""导出演示页数据：public/rag-demo.json（汇总指标 + 几个有代表性的案例）。

案例代码来自 OWASP Benchmark（GPL-2.0），这里只展示少量混淆后的片段，并注明来源和许可证。
"""

from __future__ import annotations

import json
from pathlib import Path

SRC = "OWASP Benchmark v1.2（https://github.com/OWASP-Benchmark/BenchmarkJava），GPL-2.0；代码经过混淆（去注释、换名）"


def load(p):
    p = Path(p)
    return [json.loads(l) for l in open(p, encoding="utf-8")] if p.exists() else []


def snippet(code: str, around: int, radius: int = 9) -> dict:
    lines = code.split("\n")
    lo, hi = max(1, around - radius), min(len(lines), around + radius)
    return {"start": lo, "lines": lines[lo - 1 : hi], "highlight": around}


def main() -> None:
    cases = {c["name"]: c for c in load("eval/cases.jsonl")}
    rows = load("eval/results/qwen3-8b_bare_obf_test_think.verified.jsonl")
    examples = []

    # 1-2. 大模型指出理由、核验器确认的误报（死分支 / 集合取值）
    labels = {"dead_branch": "分支永远不会执行", "key_mismatch": "从集合取出的不是用户输入", "sanitizer": "经过外部库编码"}
    for want in ("dead_branch", "key_mismatch", "sanitizer"):
        for r in rows:
            vc = r.get("verified_claim") or {}
            if not r["label"] and vc.get("type") == want and not r.get("analysis_ok"):
                c = cases[r["name"]]
                examples.append({"kind": "verified_fp", "title": f"误报，模型指出原因、核验器确认：{labels[want]}", "name": r["name"], "category": r["category"],
                                 "verdict": r["verdict"], "reason": r.get("reason", ""), "claim": vc, "check": r.get("verify_reason", ""),
                                 "code": snippet(c["code_obf"], int(vc.get("line", 1)))})
                break
    # 3. 大模型单独判会放走、但核验器拒绝的真漏洞
    for r in rows:
        if r["label"] and r["verdict"] == "false_positive" and not r.get("verify_ok"):
            c = cases[r["name"]]
            cl = (r.get("claims") or [{}])[0] or {}
            examples.append({"kind": "blocked_tp", "title": "真漏洞：模型判为误报，但理由没通过核验 → 保留给人工", "name": r["name"], "category": r["category"],
                             "verdict": r["verdict"], "reason": r.get("reason", ""), "claim": cl, "check": r.get("verify_reason", ""),
                             "code": snippet(c["code_obf"], int(cl.get("line", 1) or 1))})
            break

    summary = json.loads(Path("eval/summary.json").read_text(encoding="utf-8"))
    out = {"source": SRC, "summary": summary, "examples": examples}
    Path("public/rag-demo.json").write_text(json.dumps(out, ensure_ascii=False, indent=1), encoding="utf-8")
    print(len(examples), "examples ->", "public/rag-demo.json")


if __name__ == "__main__":
    main()
