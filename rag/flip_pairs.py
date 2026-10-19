"""反事实翻转对：把「因为控制流 / 集合取值而成为误报」的用例做最小修改，让用户输入真的流到危险函数，
得到一个「看起来几乎一样、但其实是真漏洞」的版本。模型如果是在「认套路」，会把两个版本都判成误报。

    python rag/flip_pairs.py --cases eval/cases.jsonl --split test --n 100 --out eval/flip_pairs.jsonl

翻转方法（只改一个常量 / 下标 / 键）：
- 死分支（if / 三元）：把条件里用到的那个整数常量改掉，使条件反过来
- switch：把 charAt(i) 的下标改成会落到「bar = param」那个 case 的位置
- 集合取值：把 get(i) / get("key") 改成会取到用户输入的那个下标 / 键
每个翻转后的版本都用核验器确认：任何理由都无法再证明它安全（即确实变成了真漏洞），否则丢弃。
"""

from __future__ import annotations

import argparse
import json
import random
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from verifier import candidate_claims, verify  # noqa: E402
from verifier_selftest import load_helpers  # noqa: E402

HELPERS = load_helpers(str(Path(__file__).resolve().parent.parent.parent / "data/BenchmarkJava/src/main/java/org/owasp/benchmark/helpers"))


def provably_safe(code: str, cwe: str) -> bool:
    return any(verify(code, cwe, cl, HELPERS).ok for cl in candidate_claims(code))


def flips(code: str) -> list[tuple[str, str]]:
    out = []
    # 死分支：int num = N;
    m = re.search(r"int num = (\d+);", code)
    if m:
        for v in ("0", "1000", "-1000", "500"):
            out.append((f"num={m.group(1)}→{v}", code.replace(m.group(0), f"int num = {v};", 1)))
    # switch：charAt(i)
    m = re.search(r"guess\.charAt\((\d)\)", code)
    if m:
        for i in "0123":
            if i != m.group(1):
                out.append((f"charAt({m.group(1)})→charAt({i})", code.replace(m.group(0), f"guess.charAt({i})", 1)))
    # 列表取值：get(i)
    for m in re.finditer(r"(\w+List)\.get\((\d)\)", code):
        for i in "012":
            if i != m.group(2):
                out.append((f"{m.group(1)}.get({m.group(2)})→get({i})", code.replace(m.group(0), f"{m.group(1)}.get({i})", 1)))
    # Map 取值：get("keyB") → 存放用户输入的那个键
    puts = re.findall(r'(\w+)\.put\("([^"]+)",\s*(\w+)\)', code)
    for m in re.finditer(r'(\w+)\.get\("([^"]+)"\)', code):
        for mp, key, val in puts:
            if mp == m.group(1) and key != m.group(2):
                out.append((f'get("{m.group(2)}")→get("{key}")', code.replace(m.group(0), f'{mp}.get("{key}")', 1)))
    return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--cases", default="eval/cases.jsonl")
    ap.add_argument("--split", default="test")
    ap.add_argument("--n", type=int, default=100)
    ap.add_argument("--out", default="eval/flip_pairs.jsonl")
    a = ap.parse_args()
    cases = [json.loads(l) for l in open(a.cases, encoding="utf-8")]
    pool = [c for c in cases if not c["label"] and (a.split == "all" or c["split"] == a.split)]
    random.Random(7).shuffle(pool)
    pairs = []
    for c in pool:
        code = c["code_obf"]
        if not provably_safe(code, c["cwe"]):
            continue
        for desc, new in flips(code):
            if new != code and not provably_safe(new, c["cwe"]):
                pairs.append({"name": c["name"], "category": c["category"], "cwe": c["cwe"], "edit": desc, "orig": code, "flipped": new})
                break
        if len(pairs) >= a.n:
            break
    Path(a.out).write_text("".join(json.dumps(p, ensure_ascii=False) + "\n" for p in pairs), encoding="utf-8")
    by = {}
    for p in pairs:
        by[p["category"]] = by.get(p["category"], 0) + 1
    print(len(pairs), by)


if __name__ == "__main__":
    main()
