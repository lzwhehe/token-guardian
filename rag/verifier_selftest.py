"""核验器自检（不涉及大模型）：

- 安全性：在真漏洞用例上，把所有「看起来可能」的理由都试一遍，任何一个通过 = 核验器有漏洞（会放走真漏洞）
- 覆盖面：在误报用例上，至少有一个理由能通过的比例 = 大模型在这套核验器下最多能排除多少误报
- 危险函数识别：没找到 sink 的用例（核验器无法确认，只能进复核）

    python rag/verifier_selftest.py --cases eval/cases.jsonl --helpers ../data/BenchmarkJava/src/main/java/org/owasp/benchmark/helpers
"""

from __future__ import annotations

import argparse
import collections
import json
import sys
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

import javalang

sys.path.insert(0, str(Path(__file__).resolve().parent))
from verifier import Analyzer, Unsupported, candidate_claims, verify  # noqa: E402

HELPERS: dict = {}


def load_helpers(folder: str) -> dict:
    out = {}
    for f in Path(folder).glob("*.java"):
        out[f.stem] = f.read_text(encoding="utf-8").replace("org.owasp.benchmark.helpers", "com.example.util")
    return out


def check(c: dict) -> dict:
    code = c["code_obf"]
    cu = javalang.parse.parse(code)
    try:
        an = Analyzer(cu, c["cwe"], {}, set(), set(), HELPERS)
        n_sink, n_t = an.run()
        unsupported = ""
    except Unsupported as exc:
        n_sink, n_t, unsupported = 0, 0, str(exc)
    passed = []
    for cl in candidate_claims(code):
        r = verify(code, c["cwe"], cl, HELPERS, cu=cu)
        if r.ok:
            passed.append(cl)
    return {"name": c["name"], "category": c["category"], "label": c["label"], "split": c["split"], "sinks": n_sink,
            "tainted_sinks": n_t, "unsupported": unsupported, "passed": passed}


def init(helpers):
    HELPERS.update(helpers)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--cases", default="eval/cases.jsonl")
    ap.add_argument("--helpers", required=True)
    ap.add_argument("--split", default="all")
    ap.add_argument("--out", default="eval/verifier_selftest.json")
    a = ap.parse_args()
    helpers = load_helpers(a.helpers)
    cases = [json.loads(l) for l in open(a.cases, encoding="utf-8")]
    cases = [c for c in cases if a.split == "all" or c["split"] == a.split]
    with ProcessPoolExecutor(16, initializer=init, initargs=(helpers,)) as ex:
        res = list(ex.map(check, cases, chunksize=8))
    stat = collections.defaultdict(lambda: collections.Counter())
    for r in res:
        k = r["category"]
        lab = "T" if r["label"] else "F"
        stat[k][f"{lab}_n"] += 1
        stat[k][f"{lab}_nosink"] += r["sinks"] == 0
        stat[k][f"{lab}_untainted_without_claim"] += r["sinks"] > 0 and r["tainted_sinks"] == 0
        stat[k][f"{lab}_any_claim_passes"] += bool(r["passed"])
    print("类别        真漏洞: 数量/没找到sink/有理由通过(=核验器漏洞)    误报: 数量/没找到sink/无需理由即安全/有理由通过(=上限)")
    for k, s in sorted(stat.items()):
        print(f"{k:10s}  T {s['T_n']:4d} / {s['T_nosink']:3d} / {s['T_any_claim_passes']:3d}        F {s['F_n']:4d} / {s['F_nosink']:3d} / {s['F_untainted_without_claim']:3d} / {s['F_any_claim_passes']:3d}")
    Path(a.out).write_text(json.dumps(res, ensure_ascii=False, indent=1), encoding="utf-8")
    unsup = collections.Counter(r["unsupported"] for r in res if r["unsupported"])
    print("拒绝核验的原因:", unsup.most_common(8))
    bad = [r for r in res if r["label"] and r["passed"]]
    for r in bad[:8]:
        print("UNSOUND", r["name"], r["category"], [(p["type"], p["line"]) for p in r["passed"]][:3])


if __name__ == "__main__":
    main()
