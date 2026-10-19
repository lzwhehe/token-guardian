#!/usr/bin/env node
// Measure static-rule coverage of the scanner on OWASP Benchmark v1.2 (Java).
//
// Runs the scanner's own directory scan (scanCurrentFiles -> scanLine -> scanVulnerabilityLine)
// over src/main/java/org/owasp/benchmark/testcode/*.java and joins the findings with
// expectedresults-1.2.csv for the cmdi / sqli / pathtraver / xss categories.
//
// Usage:
//   node scripts/bench_coverage.mjs [--bench .bench/BenchmarkJava] [--out eval/scanner_hits.json]
//
// Setup (once):
//   git clone --depth 1 --filter=blob:none --sparse https://github.com/OWASP-Benchmark/BenchmarkJava .bench/BenchmarkJava
//   git -C .bench/BenchmarkJava sparse-checkout set --no-cone /expectedresults-1.2.csv /src/main/java/org/owasp/benchmark/testcode/

import { promises as fs } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { scanCurrentFiles } from "../server/scanner.js";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

const CATEGORY_CWE = {
  cmdi: "CWE-78",
  sqli: "CWE-89",
  pathtraver: "CWE-22",
  xss: "CWE-79"
};

function parseArgs(argv) {
  const args = { bench: path.join(ROOT, ".bench", "BenchmarkJava"), out: path.join(ROOT, "eval", "scanner_hits.json") };
  for (let i = 0; i < argv.length; i += 1) {
    if (argv[i] === "--bench") args.bench = path.resolve(argv[++i]);
    else if (argv[i] === "--out") args.out = path.resolve(argv[++i]);
  }
  return args;
}

async function loadExpected(csvPath) {
  const text = await fs.readFile(csvPath, "utf8");
  const cases = new Map();
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith("#")) continue;
    const [name, category, real, cwe] = line.split(",").map((s) => s.trim());
    if (!CATEGORY_CWE[category]) continue;
    cases.set(name, { name, category, label: real === "true", cwe: `CWE-${cwe}` });
  }
  return cases;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const testcodeDir = path.join(args.bench, "src", "main", "java", "org", "owasp", "benchmark", "testcode");
  const cases = await loadExpected(path.join(args.bench, "expectedresults-1.2.csv"));

  const started = Date.now();
  const findings = await scanCurrentFiles(testcodeDir);
  const scanMs = Date.now() - started;

  // Group vulnerability-pattern findings by test case.
  const byCase = new Map();
  for (const finding of findings) {
    if (finding.stage !== "vulnerability-pattern") continue;
    const name = path.basename(String(finding.file)).replace(/\.java$/, "");
    if (!byCase.has(name)) byCase.set(name, []);
    byCase.get(name).push(finding);
  }

  const results = [];
  const summary = {};
  for (const category of Object.keys(CATEGORY_CWE)) {
    summary[category] = { cwe: CATEGORY_CWE[category], cases: 0, true: 0, false: 0, hitTrue: 0, hitFalse: 0 };
  }

  for (const c of [...cases.values()].sort((a, b) => a.name.localeCompare(b.name))) {
    const all = byCase.get(c.name) || [];
    const matching = all.filter((f) => f.cwe === c.cwe);
    const hit = matching.length > 0;
    const s = summary[c.category];
    s.cases += 1;
    if (c.label) s.true += 1;
    else s.false += 1;
    if (hit && c.label) s.hitTrue += 1;
    if (hit && !c.label) s.hitFalse += 1;
    results.push({
      case: c.name,
      category: c.category,
      cwe: c.cwe,
      label: c.label,
      hit,
      matchedRuleIds: [...new Set(matching.map((f) => f.ruleId))],
      sinkLines: [...new Set(matching.map((f) => f.line))].sort((a, b) => a - b),
      otherRuleIds: [...new Set(all.filter((f) => f.cwe !== c.cwe).map((f) => f.ruleId))]
    });
  }

  const totals = { cases: 0, true: 0, false: 0, hitTrue: 0, hitFalse: 0 };
  for (const s of Object.values(summary)) {
    for (const k of Object.keys(totals)) totals[k] += s[k];
  }

  const pct = (n, d) => (d ? `${((100 * n) / d).toFixed(1)}%` : "-");
  const rows = [...Object.entries(summary), ["TOTAL", { cwe: "", ...totals }]];
  console.log(`Scanned ${testcodeDir} in ${scanMs} ms (${findings.length} findings total)\n`);
  console.log(["category", "cwe", "#cases", "#true", "#false", "hit|true", "hit|false", "recall(true)", "hit-rate(false)"].join("\t"));
  for (const [name, s] of rows) {
    console.log([name, s.cwe, s.cases, s.true, s.false, s.hitTrue, s.hitFalse, pct(s.hitTrue, s.true), pct(s.hitFalse, s.false)].join("\t"));
  }

  await fs.mkdir(path.dirname(args.out), { recursive: true });
  await fs.writeFile(
    args.out,
    JSON.stringify(
      {
        benchmark: "OWASP Benchmark Java v1.2",
        generatedAt: new Date().toISOString(),
        categories: CATEGORY_CWE,
        summary: { ...summary, total: totals },
        results
      },
      null,
      2
    ) + "\n"
  );
  console.log(`\nWrote ${results.length} per-case results to ${path.relative(ROOT, args.out)}`);
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
