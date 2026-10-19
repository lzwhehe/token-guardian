"""本地 embedding 服务（Qwen3-Embedding-0.6B，最后一个 token 池化 + L2 归一化）。

    python rag/embed_server.py --model /dev/shm/pw/models/Qwen3-Embedding-0.6B --port 8012

POST /embed {"texts": [...], "query": true|false} → {"vectors": [[...], ...]}
查询会加上任务指令（Qwen3-Embedding 推荐用法），文档不加。
"""

from __future__ import annotations

import argparse
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import torch
import torch.nn.functional as F
from transformers import AutoModel, AutoTokenizer

TASK = "Given a code snippet flagged by a static security scanner, retrieve security knowledge that helps decide whether the finding is a real vulnerability or a false positive"


class Embedder:
    def __init__(self, path: str):
        self.lock = threading.Lock()  # 和 vLLM 共用一张卡，显存很紧：同一时间只算一批
        self.tok = AutoTokenizer.from_pretrained(path, padding_side="left")
        self.model = AutoModel.from_pretrained(path, torch_dtype=torch.float16).cuda().eval()

    @torch.no_grad()
    def embed(self, texts: list[str], query: bool) -> list[list[float]]:
        if query:
            texts = [f"Instruct: {TASK}\nQuery:{t}" for t in texts]
        out = []
        with self.lock:
            for i in range(0, len(texts), 8):
                batch = self.tok(texts[i : i + 8], padding=True, truncation=True, max_length=1024, return_tensors="pt").to("cuda")
                h = self.model(**batch).last_hidden_state[:, -1]
                out += F.normalize(h.float(), p=2, dim=1).cpu().tolist()
                del batch, h
            torch.cuda.empty_cache()
        return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", required=True)
    ap.add_argument("--port", type=int, default=8012)
    a = ap.parse_args()
    emb = Embedder(a.model)

    class H(BaseHTTPRequestHandler):
        def do_POST(self):  # noqa: N802
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            vecs = emb.embed(body["texts"], bool(body.get("query")))
            data = json.dumps({"vectors": vecs}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, *args):
            pass

    ThreadingHTTPServer(("127.0.0.1", a.port), H).serve_forever()


if __name__ == "__main__":
    main()
