"""把 OWASP Benchmark v1.2 整理成评测用例：只取扫描器规则覆盖的四类（cmdi / sqli / pathtraver / xss）。

    python rag/bench_prep.py --bench data/BenchmarkJava --out eval/cases.jsonl

每个用例两份代码：
- code：原文去掉文件头的许可证注释
- code_obf：混淆版 —— 改掉 BenchmarkTest 编号、类名、请求头/参数键名，去掉全部注释，
  用来检查模型是不是「背过」Benchmark 的答案（数据污染）

切分：按 类别 × 标签 分层，固定种子，20% dev（调提示词/阈值）、80% test（只在最后报一次）。
Benchmark 是 GPL-2.0：用例只在本地评测，不随仓库分发。
"""

from __future__ import annotations

import argparse
import csv
import json
import random
import re
from pathlib import Path

CATS = {"cmdi": "CWE-78", "sqli": "CWE-89", "pathtraver": "CWE-22", "xss": "CWE-79"}


def strip_license(code: str) -> str:
    return re.sub(r"\A/\*\*.*?\*/\s*", "", code, flags=re.S)


def strip_comments(code: str) -> str:
    code = re.sub(r"/\*.*?\*/", "", code, flags=re.S)
    code = re.sub(r"(?m)(^|[^:\"'])//.*$", r"\1", code)
    return re.sub(r"\n\s*\n+", "\n", code)


# Benchmark 里会「暗示答案」的字符串和函数名：换成中性名字，只改名不改语义
TELLS = [
    ('"This_should_always_happen"', '"v_const"'),
    ('"moresafe"', '"v2"'),
    ('"alsosafe"', '"v3"'),
    ('"safe"', '"v1"'),
    ('"_SafeStuff"', '"_Stuff"'),
    ('" SafeStuff"', '" Stuff"'),
    ('"safe!"', '"v0!"'),
    ("getInsecureOSCommandString", "getOSCommandStringAlt"),
    ("org.owasp.benchmark.helpers.", "com.example.util."),
    ("org.owasp.benchmark.testcode", "com.example.app"),
    ("org.owasp.benchmark", "com.example"),
]


def obfuscate(code: str, name: str, rng: random.Random) -> str:
    tag = "".join(rng.choice("abcdefghijklmnopqrstuvwxyz") for _ in range(6))
    out = strip_comments(code)
    out = out.replace(name, f"Handler_{tag}")
    out = re.sub(r"BenchmarkTest\d{5}", f"Handler_{tag}", out)
    out = re.sub(r'"/(cmdi|sqli|pathtraver|xss)-\d+/', '"/app/', out)
    for a, b in TELLS:
        out = out.replace(a, b)
    out = re.sub(r'"Safe([A-Z][a-z]+)"', r'"\1"', out)
    return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--bench", required=True)
    ap.add_argument("--out", default="eval/cases.jsonl")
    ap.add_argument("--dev-frac", type=float, default=0.2)
    ap.add_argument("--seed", type=int, default=20261020)
    a = ap.parse_args()
    bench = Path(a.bench)
    src = bench / "src/main/java/org/owasp/benchmark/testcode"
    rows = [r for r in csv.reader(open(bench / "expectedresults-1.2.csv", encoding="utf-8")) if r and not r[0].startswith("#")]
    rng = random.Random(a.seed)
    cases = []
    for name, cat, real, cwe in rows:
        if cat not in CATS:
            continue
        code = strip_license((src / f"{name}.java").read_text(encoding="utf-8"))
        cases.append({"name": name, "category": cat, "cwe": CATS[cat], "label": real == "true", "code": code, "code_obf": obfuscate(code, name, rng)})
    groups = {}
    for c in cases:
        groups.setdefault((c["category"], c["label"]), []).append(c)
    for g in groups.values():
        rng.shuffle(g)
        k = round(len(g) * a.dev_frac)
        for i, c in enumerate(g):
            c["split"] = "dev" if i < k else "test"
    Path(a.out).parent.mkdir(parents=True, exist_ok=True)
    with open(a.out, "w", encoding="utf-8") as fh:
        for c in sorted(cases, key=lambda c: c["name"]):
            fh.write(json.dumps(c, ensure_ascii=False) + "\n")
    stat = {}
    for c in cases:
        k = f"{c['split']}/{c['category']}/{'T' if c['label'] else 'F'}"
        stat[k] = stat.get(k, 0) + 1
    print(len(cases), json.dumps(dict(sorted(stat.items())), ensure_ascii=False))


if __name__ == "__main__":
    main()
