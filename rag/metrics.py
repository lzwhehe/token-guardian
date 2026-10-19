"""研判指标。

三分类口径（红队评审 P1-5）：
- dismissed（排除）：最终结论为 false_positive，且（如果启用核验器）理由通过核验
- review（复核）：uncertain，或者判了误报但理由没通过核验
- kept（保留）：real

主指标：
- fp_dismiss_rate = 被排除的误报 / 全部误报（越高，替人省下的复核越多）
- tp_dismissed    = 被排除的真漏洞数（代价最高的错误，目标为 0）
- tp_retention    = 1 − tp_dismissed / 全部真漏洞（复核也算保留）
- benchmark_score = TPR − FPR，其中「被标记」= 未被排除
置信区间：自助法（bootstrap），2000 次重采样。
"""

from __future__ import annotations

import json
import random
import sys
from pathlib import Path


def outcome(r: dict, verified: bool | None = None) -> str:
    if r["verdict"] == "false_positive":
        if verified is None or verified:
            return "dismissed"
        return "review"
    if r["verdict"] == "uncertain":
        return "review"
    return "kept"


def summarize(rows: list[dict], key=lambda r: outcome(r)) -> dict:
    T = [r for r in rows if r["label"]]
    F = [r for r in rows if not r["label"]]
    o = {id(r): key(r) for r in rows}
    td = sum(o[id(r)] == "dismissed" for r in T)
    fd = sum(o[id(r)] == "dismissed" for r in F)
    tpr = 1 - td / len(T) if T else 0
    fpr = 1 - fd / len(F) if F else 0
    return {
        "n": len(rows), "true": len(T), "false": len(F),
        "fp_dismissed": fd, "fp_dismiss_rate": fd / len(F) if F else 0,
        "tp_dismissed": td, "tp_retention": tpr,
        "review_rate": sum(o[id(r)] == "review" for r in rows) / len(rows) if rows else 0,
        "benchmark_score": tpr - fpr,
    }


def bootstrap(rows: list[dict], metric: str, key=lambda r: outcome(r), n: int = 2000, seed: int = 0) -> tuple[float, float]:
    rng = random.Random(seed)
    vals = []
    for _ in range(n):
        s = [rows[rng.randrange(len(rows))] for _ in rows]
        vals.append(summarize(s, key)[metric])
    vals.sort()
    return vals[int(0.025 * n)], vals[int(0.975 * n)]


def load(path: str) -> list[dict]:
    return [json.loads(l) for l in open(path, encoding="utf-8")]


if __name__ == "__main__":
    for p in sys.argv[1:]:
        rows = load(p)
        s = summarize(rows)
        lo, hi = bootstrap(rows, "fp_dismiss_rate")
        print(f"{Path(p).stem:42s} n={s['n']} 误报排除 {s['fp_dismissed']}/{s['false']} ({s['fp_dismiss_rate']:.1%} [{lo:.1%},{hi:.1%}])"
              f"  真漏洞被排除 {s['tp_dismissed']}/{s['true']} (保留 {s['tp_retention']:.1%})  复核 {s['review_rate']:.1%}  score {s['benchmark_score']:+.3f}")
        by = {}
        for r in rows:
            by.setdefault(r["category"], []).append(r)
        for cat, rs in sorted(by.items()):
            c = summarize(rs)
            print(f"    {cat:10s} 误报排除 {c['fp_dismissed']:3d}/{c['false']:3d}  真漏洞被排除 {c['tp_dismissed']:3d}/{c['true']:3d}")
