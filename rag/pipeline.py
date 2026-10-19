"""最终研判流程（评测定版的配置）：程序分析 ∪ 大模型指出位置 + 确定性核验。

decide(code, cwe) →
  dismissed  核验器证明安全（程序分析直接证明，或大模型指出的某个理由核验通过）
  review     需要人工复核（大模型认为可能是误报 / 拿不准，但没有能核验的理由）
  kept       保留告警（大模型认为是真实漏洞，且没有任何理由能证明安全）

判定权在核验器：大模型的结论只决定 kept 还是 review，永远不能单独让告警被排除。
"""

from __future__ import annotations

import os
from pathlib import Path

from judge import build_prompt, call
from verifier import verify

TYPES = ("dead_branch", "key_mismatch", "sanitizer", "overwritten", "param_query", "no_taint")
BASE_URL = os.environ.get("RAG_LLM_BASE_URL", "http://127.0.0.1:8011/v1")
MODEL = os.environ.get("RAG_LLM_MODEL", "qwen3-8b")


def analysis_proves_safe(code: str, cwe: str, helpers: dict | None, flagged_lines: list | None = None) -> bool:
    lines = code.splitlines()
    first = next((i for i, l in enumerate(lines, 1) if l.strip() and not l.strip().startswith(("package", "import", "//", "*", "/*"))), 1)
    return verify(code, cwe, {"type": "no_taint", "line": first, "expr": lines[first - 1].strip()}, helpers, flagged_lines=flagged_lines).ok


def first_verified(code: str, cwe: str, claims: list, helpers: dict | None, flagged_lines: list | None = None):
    for cl in (claims or [])[:3]:
        cl = cl or {}
        for t in (cl.get("type"), *[x for x in TYPES if x != cl.get("type")]):
            v = verify(code, cwe, {**cl, "type": t}, helpers, flagged_lines=flagged_lines)
            if v.ok:
                return {**cl, "type": t, "check": v.reason}
    return None


def decide(code: str, cwe: str, helpers: dict | None = None, thinking: bool = True, flagged_lines: list | None = None) -> dict:
    if analysis_proves_safe(code, cwe, helpers, flagged_lines):
        return {"decision": "dismissed", "by": "analysis", "verdict": None, "claims": [], "verified_claim": None,
                "reason": "程序分析确认危险函数不接收用户输入"}
    r = call(BASE_URL, MODEL, build_prompt(cwe, code), thinking=thinking)
    vc = first_verified(code, cwe, r.get("claims"), helpers, flagged_lines)
    if vc:
        return {"decision": "dismissed", "by": "llm+verifier", "verdict": r["verdict"], "claims": r.get("claims"), "verified_claim": vc,
                "reason": r.get("reason", "")}
    return {"decision": "kept" if r["verdict"] == "real" else "review", "by": "llm", "verdict": r["verdict"], "claims": r.get("claims"),
            "verified_claim": None, "reason": r.get("reason", "")}
