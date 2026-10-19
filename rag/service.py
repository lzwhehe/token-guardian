"""研判服务：扫描器（Node）通过 HTTP 调用。只依赖标准库 + 本目录模块。

    RAG_LLM_BASE_URL=http://127.0.0.1:8011/v1 RAG_LLM_MODEL=qwen3-8b python rag/service.py --port 8790

POST /triage {"cwe": "CWE-78", "file": "Foo.java", "code": "<完整文件内容>"}
  → {"decision": "dismissed|review|kept", "by": ..., "verdict": ..., "verified_claim": {...}|null, "reason": ...}
GET /health → {"ok": true}

目前核验器只支持 Java；其它语言直接返回 review（不做未经核验的排除）。
"""

from __future__ import annotations

import argparse
import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from pipeline import decide  # noqa: E402

SUPPORTED = {"CWE-78", "CWE-89", "CWE-22", "CWE-79"}
MAX_BYTES = 600_000  # 120 KB 的文件做 JSON 转义后可能翻好几倍


class Handler(BaseHTTPRequestHandler):
    def _send(self, code: int, obj: dict) -> None:
        data = json.dumps(obj, ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):  # noqa: N802
        self._send(200 if self.path == "/health" else 404, {"ok": self.path == "/health"})

    def do_POST(self):  # noqa: N802
        if self.path != "/triage":
            return self._send(404, {"error": "not found"})
        try:
            n = int(self.headers.get("Content-Length", ""))
        except ValueError:
            return self._send(411, {"error": "Content-Length required"})
        if n <= 0 or n > MAX_BYTES:
            return self._send(413, {"error": "bad body size"})
        try:
            body = json.loads(self.rfile.read(n))
            cwe, code, name = str(body["cwe"]), str(body["code"]), str(body.get("file", ""))
            lines = [int(x) for x in (body.get("lines") or [])][:50]
        except Exception:
            return self._send(400, {"error": "bad request"})
        if not name.endswith(".java") or cwe not in SUPPORTED:
            return self._send(200, {"decision": "review", "by": "unsupported", "verdict": None, "verified_claim": None,
                                    "reason": "核验器目前只支持 Java 的命令注入 / SQL 注入 / 路径遍历 / XSS，其余告警保留给人工复核"})
        try:
            return self._send(200, decide(code, cwe, helpers=None, flagged_lines=lines or None))
        except Exception as exc:  # 研判失败不能变成「排除」
            return self._send(200, {"decision": "review", "by": "error", "verdict": None, "verified_claim": None, "reason": f"研判失败：{type(exc).__name__}"})

    def log_message(self, *args):
        pass


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8790)
    a = ap.parse_args()
    ThreadingHTTPServer((a.host, a.port), Handler).serve_forever()


if __name__ == "__main__":
    main()
