"""各实验组需要的额外材料。

- card：可信知识库里该 CWE 的规则卡片（CWE 定义 + 缓解措施），按 CWE 精确取，不做检索
- context：从被扫描仓库里「按符号精确检索」被调用的辅助类 / 方法源码（不可信数据区）
- knowledge：在可信知识库里做混合检索 —— LangChain 的 BM25Retriever + FAISS 向量检索
  （Qwen3-Embedding-0.6B），两路结果用 RRF 融合，按 CWE 家族过滤，取前 3 条
- random_kb：与 knowledge 同样条数的随机条目（来自别的 CWE），对照「只是提示词变长了」的影响
"""

from __future__ import annotations

import hashlib
import json
import random
import re
import urllib.request
from pathlib import Path

from langchain_community.retrievers import BM25Retriever
from langchain_community.vectorstores import FAISS
from langchain_core.documents import Document
from langchain_core.embeddings import Embeddings

ROOT = Path(__file__).resolve().parent.parent
FAMILY = {
    "CWE-78": {"CWE-78", "CWE-77"},
    "CWE-89": {"CWE-89", "CWE-564"},
    "CWE-22": {"CWE-22", "CWE-23", "CWE-36", "CWE-73"},
    "CWE-79": {"CWE-79", "CWE-80", "CWE-83"},
}
HELPERS_DIR = ROOT.parent / "data/BenchmarkJava/src/main/java/org/owasp/benchmark/helpers"
TOP_K = 3


class HttpEmbeddings(Embeddings):
    """把本地 embedding 服务包装成 LangChain 的 Embeddings 接口。"""

    def __init__(self, url: str = "http://127.0.0.1:8012/embed"):
        self.url = url

    def _post(self, texts, query):
        req = urllib.request.Request(self.url, data=json.dumps({"texts": texts, "query": query}).encode(), headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=300) as r:
            return json.loads(r.read())["vectors"]

    def embed_documents(self, texts):
        return self._post(list(texts), False)

    def embed_query(self, text):
        return self._post([text], True)[0]


def code_tokens(text: str) -> list[str]:
    return [t.lower() for t in re.findall(r"[A-Za-z_][A-Za-z0-9_]*|\d+", text)]


def load_kb(path: Path = ROOT / "kb/records.jsonl") -> list[dict]:
    return [json.loads(l) for l in open(path, encoding="utf-8")]


def rule_card(kb: list[dict], cwe: str, limit: int = 1600) -> str:
    recs = [r for r in kb if r["cwe"] == cwe]
    summ = next((r for r in recs if r["kind"] == "summary"), None)
    mitig = [r for r in recs if r["kind"] == "mitigation"][:4]
    parts = [f"{summ['title']}：{summ['text'][:600]}"] if summ else []
    parts += [f"- {m['text'][:300]}" for m in mitig]
    return ("\n".join(parts))[:limit] + "\n（来源：MITRE CWE）"


def load_helpers() -> dict:
    out = {}
    if HELPERS_DIR.exists():
        for f in HELPERS_DIR.glob("*.java"):
            out[f.stem] = f.read_text(encoding="utf-8").replace("org.owasp.benchmark.helpers", "com.example.util")
    return out


def method_source(src: str, name: str, limit: int = 1200) -> str:
    m = re.search(rf"(public|private|protected|static)[^;{{]*\b{re.escape(name)}\s*\([^)]*\)[^{{;]*\{{", src)
    if not m:
        return ""
    i, depth = m.end(), 1
    while i < len(src) and depth:
        depth += {"{": 1, "}": -1}.get(src[i], 0)
        i += 1
    return src[m.start() : i][:limit]


def repo_context(code: str, helpers: dict, limit: int = 3500) -> str:
    """按符号精确检索：代码里用到的 com.example.util.X.method → 取出 X.method 的源码。"""
    parts = []
    for cls, meth in sorted(set(re.findall(r"com\.example\.util\.(\w+)\.(\w+)\s*\(", code))):
        src = helpers.get(cls)
        if src:
            body = method_source(src, meth)
            if body:
                parts.append(f"// {cls}.{meth}\n{body}")
    if "ThingInterface" in code or "ThingFactory" in code:
        for cls in ("ThingFactory", "Thing1", "Thing2"):
            src = helpers.get(cls)
            if src:
                for meth in ("createThing", "doSomething"):
                    body = method_source(src, meth)
                    if body:
                        parts.append(f"// {cls}.{meth}\n{body}")
    if "SeparateClassRequest" in code and "SeparateClassRequest" in helpers:
        parts.append("// SeparateClassRequest\n" + helpers["SeparateClassRequest"][:1200])
    return "\n\n".join(parts)[:limit]


class Retriever:
    """LangChain 混合检索：每个 CWE 家族建一套 BM25 + FAISS，结果按 RRF 融合。"""

    def __init__(self, kb: list[dict], k: int = 10, rrf_k: int = 60):
        self.k, self.rrf_k = k, rrf_k
        self.by_id = {r["id"]: r for r in kb}
        emb = HttpEmbeddings()
        self.idx = {}
        for cwe, fam in FAMILY.items():
            docs = [Document(page_content=f"{r['title']}\n{r['text']}\n{r.get('code', '')}", metadata={"id": r["id"]}) for r in kb if r["cwe"] in fam and r["kind"] != "summary"]
            bm25 = BM25Retriever.from_documents(docs, preprocess_func=code_tokens, k=k)
            vs = FAISS.from_documents(docs, emb)
            self.idx[cwe] = (bm25, vs.as_retriever(search_kwargs={"k": k}))

    def search(self, cwe: str, query: str, top: int = TOP_K) -> list[dict]:
        bm25, dense = self.idx[cwe]
        scores: dict = {}
        for retr in (bm25, dense):
            for rank, d in enumerate(retr.invoke(query)):
                scores[d.metadata["id"]] = scores.get(d.metadata["id"], 0) + 1 / (self.rrf_k + rank + 1)
        best = sorted(scores, key=lambda i: -scores[i])[:top]
        return [self.by_id[i] for i in best]


class ArmBuilder:
    def __init__(self, arm: str, variant: str):
        self.arm = arm
        self.kb = load_kb()
        self.helpers = load_helpers()
        self.retriever = Retriever(self.kb) if arm in ("knowledge", "full") else None

    def materials(self, case: dict, code: str) -> dict:
        kw = {}
        cwe = case["cwe"]
        if self.arm in ("card", "knowledge", "random_kb", "full"):
            kw["card"] = rule_card(self.kb, cwe)
        if self.arm in ("context", "full"):
            kw["context"] = repo_context(code, self.helpers)
        if self.arm in ("knowledge", "full"):
            kw["knowledge"] = self.retriever.search(cwe, code[:3000])
        if self.arm == "random_kb":
            seed = int(hashlib.sha256(case["name"].encode()).hexdigest()[:8], 16)
            pool = [r for r in self.kb if r["cwe"] not in FAMILY[cwe] and r["kind"] != "summary"]
            kw["knowledge"] = random.Random(seed).sample(pool, TOP_K)
        return kw
