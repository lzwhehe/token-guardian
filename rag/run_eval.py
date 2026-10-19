"""跑一个实验组：对开发集或测试集的每个用例调用研判器，结果逐行写入 eval/results/。

    python rag/run_eval.py --arm bare --split dev --variant obf --model qwen3-8b

已经跑过的用例会跳过（可断点续跑）。
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from judge import PROMPT_VERSION, build_prompt, call  # noqa: E402


def load_cases(path: str, split: str) -> list[dict]:
    cs = [json.loads(l) for l in open(path, encoding="utf-8")]
    return [c for c in cs if split == "all" or c["split"] == split]


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--arm", default="bare")
    ap.add_argument("--split", default="dev")
    ap.add_argument("--variant", default="obf", choices=["obf", "orig"])
    ap.add_argument("--cases", default="eval/cases.jsonl")
    ap.add_argument("--base-url", default="http://127.0.0.1:8011/v1")
    ap.add_argument("--model", default="qwen3-8b")
    ap.add_argument("--thinking", action="store_true")
    ap.add_argument("--workers", type=int, default=32)
    ap.add_argument("--limit", type=int, default=0)
    a = ap.parse_args()

    tag = f"{a.model}_{a.arm}_{a.variant}_{a.split}" + ("_think" if a.thinking else "")
    out = Path("eval/results") / f"{tag}.jsonl"
    out.parent.mkdir(parents=True, exist_ok=True)
    done = {json.loads(l)["name"] for l in open(out, encoding="utf-8")} if out.exists() else set()
    cases = [c for c in load_cases(a.cases, a.split) if c["name"] not in done]
    if a.limit:
        cases = cases[: a.limit]

    # 实验组需要的额外材料由 context.py / retrieve.py 提供（按需导入）
    extras = None
    if a.arm != "bare":
        from arms import ArmBuilder  # noqa: E402

        extras = ArmBuilder(a.arm, a.variant)

    def one(c: dict) -> dict:
        code = c["code_obf"] if a.variant == "obf" else c["code"]
        kw = extras.materials(c, code) if extras else {}
        prompt = build_prompt(c["cwe"], code, **kw)
        t = time.time()
        r = call(a.base_url, a.model, prompt, thinking=a.thinking)
        return {
            "name": c["name"], "category": c["category"], "cwe": c["cwe"], "label": c["label"], "split": c["split"],
            "arm": a.arm, "variant": a.variant, "model": a.model, "prompt_version": PROMPT_VERSION,
            "verdict": r["verdict"], "p": r["p"], "claims": r.get("claims", []), "knowledge_ids": r.get("knowledge_ids", []),
            "offered_knowledge": [k["id"] for k in kw.get("knowledge", [])], "reason": r.get("reason", ""),
            "prompt_chars": len(prompt), "latency_s": round(time.time() - t, 2), "usage": r.get("usage", {}),
        }

    started = time.time()
    with open(out, "a", encoding="utf-8") as fh, ThreadPoolExecutor(a.workers) as ex:
        for i, res in enumerate(ex.map(one, cases), 1):
            fh.write(json.dumps(res, ensure_ascii=False) + "\n")
            fh.flush()
            if i % 50 == 0:
                print(f"{i}/{len(cases)} {time.time() - started:.0f}s", flush=True)
    print(f"done {tag}: {len(cases)} new cases in {time.time() - started:.0f}s -> {out}")


if __name__ == "__main__":
    main()
