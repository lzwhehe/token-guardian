import assert from "node:assert/strict";
import test from "node:test";
import { summarizeLocalRag } from "../server/aiAnalysis.js";

const group = { file: "Foo.java", severity: "high", findings: [] };

test("all findings dismissed by the verifier -> unlikely, low risk, cites the verified line", () => {
  const r = summarizeLocalRag(group, [
    { cwe: "CWE-78", decision: "dismissed", by: "llm+verifier", verified_claim: { type: "dead_branch", line: 27, expr: "if (...)" } }
  ]);
  assert.equal(r.exploitability, "unlikely");
  assert.equal(r.riskRating, "low");
  assert.match(r.falsePositiveSignals[0], /第 27 行/);
  assert.match(r.falsePositiveSignals[0], /核验器确认/);
});

test("any kept finding -> plausible, original severity kept", () => {
  const r = summarizeLocalRag(group, [
    { cwe: "CWE-78", decision: "dismissed", by: "analysis", verified_claim: null },
    { cwe: "CWE-89", decision: "kept", by: "llm", reason: "user input concatenated into SQL" }
  ]);
  assert.equal(r.exploitability, "plausible");
  assert.equal(r.riskRating, "high");
});

test("unverified false-positive opinion never becomes a dismissal", () => {
  const r = summarizeLocalRag(group, [{ cwe: "CWE-22", decision: "review", by: "llm", verdict: "false_positive" }]);
  assert.equal(r.exploitability, "conditional");
  assert.deepEqual(r.falsePositiveSignals, []);
});

test("a dismissed CWE-89 does not downgrade a file that also has an unsupported finding (e.g. leaked key)", () => {
  const mixed = { file: "Foo.java", severity: "critical", findings: [{ cwe: "CWE-89" }, { cwe: "CWE-798" }] };
  const r = summarizeLocalRag(mixed, [{ cwe: "CWE-89", decision: "dismissed", by: "analysis", verified_claim: null }]);
  assert.equal(r.riskRating, "critical");
  assert.notEqual(r.exploitability, "unlikely");
});

test("service errors become review, never dismissal", () => {
  const r = summarizeLocalRag(group, [{ cwe: "CWE-78", decision: "review", by: "error", reason: "timeout" }]);
  assert.equal(r.exploitability, "conditional");
  assert.deepEqual(r.falsePositiveSignals, []);
});
