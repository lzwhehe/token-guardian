"""构建只读知识库：CWE 条目 + OWASP Cheat Sheet 章节 → kb/records.jsonl + kb/manifest.json

    python rag/kb_build.py --cwe-zip data/cwec_latest.xml.zip --cheatsheets data/CheatSheetSeries/cheatsheets --out kb

- 每条记录：{id, cwe, kind, language, title, text, code, source, license}
- kind：summary | mitigation | unsafe_example | safe_example | guidance
- manifest 里有每条记录的 sha256 和来源文件，任何人都能审计知识库里混进了什么
- 永不索引被扫描的仓库和评测集代码（这里只读两类公开的规范文本）
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import zipfile
from pathlib import Path
from xml.etree import ElementTree as ET

# 扫描器规则覆盖的 CWE（server/rules/vulnerabilityRules.js）
CWES = {"78", "89", "22", "79", "918", "502", "942", "1321", "94", "73", "23", "36", "77", "564", "80", "83"}
CHEATSHEETS = {
    "OS_Command_Injection_Defense_Cheat_Sheet.md": ["78", "77"],
    "SQL_Injection_Prevention_Cheat_Sheet.md": ["89"],
    "Query_Parameterization_Cheat_Sheet.md": ["89"],
    "Injection_Prevention_Cheat_Sheet.md": ["78", "89", "94"],
    "Injection_Prevention_in_Java_Cheat_Sheet.md": ["78", "89", "94"],
    "Cross_Site_Scripting_Prevention_Cheat_Sheet.md": ["79"],
    "DOM_based_XSS_Prevention_Cheat_Sheet.md": ["79"],
    "Input_Validation_Cheat_Sheet.md": ["22", "78", "89", "79"],
    "File_Upload_Cheat_Sheet.md": ["22"],
    "Server_Side_Request_Forgery_Prevention_Cheat_Sheet.md": ["918"],
    "Deserialization_Cheat_Sheet.md": ["502"],
    "Nodejs_Security_Cheat_Sheet.md": ["78", "22", "79", "1321"],
    "Prototype_Pollution_Prevention_Cheat_Sheet.md": ["1321"],
}
CWE_LICENSE = "CWE © The MITRE Corporation. Used under the CWE Terms of Use (https://cwe.mitre.org/about/termsofuse.html)."
OWASP_LICENSE = "OWASP Cheat Sheet Series, CC BY-SA 4.0 (https://github.com/OWASP/CheatSheetSeries)"
NS = "{http://cwe.mitre.org/cwe-7}"


def _text(el) -> str:
    if el is None:
        return ""
    return re.sub(r"\s+", " ", "".join(el.itertext())).strip()


def _code(el) -> str:
    lines = []
    for node in el.iter():
        if node.tag.endswith("div") or node.tag.endswith("br"):
            lines.append("\n")
        if node.text:
            lines.append(node.text)
        if node.tail:
            lines.append(node.tail)
    return re.sub(r"\n{3,}", "\n\n", "".join(lines)).strip()


def cwe_records(zip_path: Path) -> list[dict]:
    with zipfile.ZipFile(zip_path) as z:
        xml = z.read(next(n for n in z.namelist() if n.endswith(".xml")))
    root = ET.fromstring(xml)
    out = []
    for w in root.iter(f"{NS}Weakness"):
        cid = w.get("ID")
        if cid not in CWES:
            continue
        name = w.get("Name")
        src = f"https://cwe.mitre.org/data/definitions/{cid}.html"
        base = {"cwe": f"CWE-{cid}", "source": src, "license": CWE_LICENSE}
        desc = " ".join(filter(None, [_text(w.find(f"{NS}Description")), _text(w.find(f"{NS}Extended_Description"))]))
        out.append({**base, "kind": "summary", "language": "any", "title": f"CWE-{cid} {name}", "text": desc, "code": ""})
        for i, m in enumerate(w.iter(f"{NS}Mitigation")):
            t = _text(m.find(f"{NS}Description"))
            phase = _text(m.find(f"{NS}Phase"))
            if t:
                out.append({**base, "kind": "mitigation", "language": "any", "title": f"CWE-{cid} 缓解措施 {i + 1}（{phase}）", "text": t, "code": ""})
        for j, ex in enumerate(w.iter(f"{NS}Demonstrative_Example")):
            intro = _text(ex.find(f"{NS}Intro_Text"))
            body = " ".join(_text(b) for b in ex.findall(f"{NS}Body_Text"))
            for k, code in enumerate(ex.findall(f"{NS}Example_Code")):
                nature = (code.get("Nature") or "").lower()
                kind = "safe_example" if nature in ("good", "mitigation") else "unsafe_example"
                out.append({
                    **base, "kind": kind, "language": (code.get("Language") or "any").lower(),
                    "title": f"CWE-{cid} 示例 {j + 1}.{k + 1}（{'安全写法' if kind == 'safe_example' else '不安全写法'}）",
                    "text": f"{intro} {body}".strip(), "code": _code(code)[:2500],
                })
    return out


def cheatsheet_records(folder: Path) -> list[dict]:
    out = []
    for fname, cwes in CHEATSHEETS.items():
        f = folder / fname
        if not f.exists():
            continue
        md = f.read_text(encoding="utf-8")
        sections = re.split(r"(?m)^(#{2,3} .+)$", md)
        # sections: [preamble, heading1, body1, heading2, body2, ...]
        for h, body in zip(sections[1::2], sections[2::2]):
            text = body.strip()
            if len(text) < 120:
                continue
            code = "\n\n".join(re.findall(r"```[a-zA-Z]*\n(.*?)```", text, re.S))[:2500]
            prose = re.sub(r"```.*?```", " ", text, flags=re.S)
            prose = re.sub(r"\s+", " ", prose).strip()[:3000]
            anchor = re.sub(r"[^a-z0-9]+", "-", h.lstrip("# ").lower()).strip("-")
            for cwe in cwes:
                out.append({
                    "cwe": f"CWE-{cwe}", "kind": "guidance", "language": "any",
                    "title": f"{fname.replace('_', ' ').replace('.md', '')} · {h.lstrip('# ').strip()}",
                    "text": prose, "code": code,
                    "source": f"https://cheatsheetseries.owasp.org/cheatsheets/{fname.replace('.md', '.html')}#{anchor}",
                    "license": OWASP_LICENSE,
                })
    return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--cwe-zip", required=True)
    ap.add_argument("--cheatsheets", required=True)
    ap.add_argument("--out", default="kb")
    a = ap.parse_args()
    recs = cwe_records(Path(a.cwe_zip)) + cheatsheet_records(Path(a.cheatsheets))
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    manifest = []
    with open(out / "records.jsonl", "w", encoding="utf-8") as fh:
        for i, r in enumerate(recs):
            body = json.dumps({k: r[k] for k in sorted(r)}, ensure_ascii=False, sort_keys=True)
            sha = hashlib.sha256(body.encode("utf-8")).hexdigest()
            r = {"id": f"K{i:04d}", **r, "sha256": sha}
            fh.write(json.dumps(r, ensure_ascii=False) + "\n")
            manifest.append({"id": r["id"], "cwe": r["cwe"], "kind": r["kind"], "source": r["source"], "sha256": sha})
    (out / "manifest.json").write_text(json.dumps({"count": len(manifest), "records": manifest}, ensure_ascii=False, indent=1), encoding="utf-8")
    by = {}
    for r in recs:
        by.setdefault(r["cwe"], {}).setdefault(r["kind"], 0)
        by[r["cwe"]][r["kind"]] += 1
    print(len(recs), "records")
    for k in sorted(by):
        print(" ", k, by[k])


if __name__ == "__main__":
    main()
