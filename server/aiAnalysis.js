import { getVault, persistAnalysisResult } from "./vault.js";

const providerConfigs = {
  openai: {
    label: "OpenAI",
    defaultModel: "gpt-5.4-mini",
    envKeys: ["OPENAI_API_KEY", "AI_SECURITY_API_KEY"]
  },
  deepseek: {
    label: "DeepSeek",
    defaultModel: "deepseek-v4-pro",
    envKeys: ["DEEPSEEK_API_KEY", "AI_SECURITY_DEEPSEEK_API_KEY"]
  },
  // 本地研判服务（rag/service.py）：本地大模型提出候选理由，确定性核验器确认后才允许判为误报。
  // 不需要 API Key，代码不出内网。
  "local-rag": {
    label: "本地研判（大模型 + 核验器）",
    defaultModel: "qwen3-8b",
    envKeys: [],
    keyless: true
  }
};

const RAG_TRIAGE_URL = process.env.RAG_TRIAGE_URL || "http://127.0.0.1:8790";

const MAX_ANALYSIS_FINDINGS = 8;
const MAX_FILE_BYTES = 120_000;
const CODE_WINDOW = 80;

export async function analyzeHighRiskFiles({ apiKey, findingKeys = [], model, provider = "openai" } = {}) {
  const { resolvedModel, resolvedProvider, resolvedApiKey } = resolveAiProvider({ apiKey, model, provider });

  const { vault } = await getVault();
  const highRiskGroups = groupHighRiskFindings(vault.findings || []);
  const selectedGroups = findingKeys.length
    ? highRiskGroups.filter((group) => group.findings.some((finding) => findingKeys.includes(finding.key)))
    : highRiskGroups.slice(0, MAX_ANALYSIS_FINDINGS);

  if (!selectedGroups.length) {
    return {
      provider,
      model: resolvedModel,
      analyzedAt: new Date().toISOString(),
      analyses: [],
      message: "没有找到可分析的高风险文件。"
    };
  }

  const analyses = [];
  for (const group of selectedGroups.slice(0, MAX_ANALYSIS_FINDINGS)) {
    const codeEvidence = await collectCodeEvidence(group, { includeFullContent: resolvedProvider === "local-rag" });
    const result = await requestAiAnalysis({
      apiKey: resolvedApiKey,
      provider: resolvedProvider,
      model: resolvedModel,
      group,
      codeEvidence
    });
    delete codeEvidence.fullContent;
    const persisted = await persistAnalysisResult({
      id: `analysis-${fingerprint(`${group.file}:${Date.now()}`)}`,
      findingKeys: group.findings.map((finding) => finding.key),
      file: group.file,
      repository: group.repository,
      status: "completed",
      provider: resolvedProvider,
      model: resolvedModel,
      result,
      codeEvidence: {
        status: codeEvidence.status,
        source: codeEvidence.source,
        lines: codeEvidence.lines,
        truncated: codeEvidence.truncated,
        redacted: true
      }
    });

    analyses.push({
      file: group.file,
      repository: group.repository,
      findingKeys: group.findings.map((finding) => finding.key),
      codeEvidence,
      result,
      vault: persisted.vault
    });
  }

  return {
    provider: resolvedProvider,
    model: resolvedModel,
    analyzedAt: new Date().toISOString(),
    analyses,
    vault: analyses.at(-1)?.vault || vault
  };
}

export async function testAiProviderAvailability({ apiKey, model, provider = "openai" } = {}) {
  const { providerConfig, resolvedModel, resolvedProvider, resolvedApiKey } = resolveAiProvider({
    apiKey,
    model,
    provider
  });

  if (resolvedProvider === "local-rag") {
    const response = await fetch(`${RAG_TRIAGE_URL}/health`);
    if (!response.ok) throw new Error(`本地研判服务不可用（${response.status}）`);
  } else if (resolvedProvider === "deepseek") {
    await requestChatCompletionsAvailability({
      apiKey: resolvedApiKey,
      model: resolvedModel,
      endpoint: "https://api.deepseek.com/chat/completions"
    });
  } else {
    await requestOpenAiResponsesAvailability({ apiKey: resolvedApiKey, model: resolvedModel });
  }

  return {
    ok: true,
    provider: resolvedProvider,
    providerLabel: providerConfig.label,
    model: resolvedModel,
    checkedAt: new Date().toISOString(),
    message: `${providerConfig.label} API Key 可用，模型响应正常。`
  };
}

export function groupHighRiskFindings(findings = []) {
  const groups = new Map();
  const highRiskFindings = findings.filter(
    (finding) =>
      finding.stage !== "risk-file-name" &&
      (["critical", "high"].includes(finding.severity) ||
        finding.exploitability?.confidence === "high" ||
        finding.actionable === true ||
        finding.evidenceLevel === "credential")
  );

  for (const finding of highRiskFindings) {
    const key = `${finding.repository || "unknown"}:${finding.file}`;
    const current = groups.get(key) || {
      repository: finding.repository,
      file: finding.file,
      fileUrl: finding.fileUrl,
      severity: finding.severity,
      findings: []
    };
    current.severity = higherSeverity(current.severity, finding.severity);
    if (!current.fileUrl && finding.fileUrl) current.fileUrl = finding.fileUrl;
    current.findings.push(finding);
    groups.set(key, current);
  }

  return [...groups.values()].sort(
    (left, right) =>
      severityRank(right.severity) - severityRank(left.severity) ||
      right.findings.length - left.findings.length
  );
}

async function collectCodeEvidence(group, { includeFullContent = false } = {}) {
  if (!group.fileUrl || !group.fileUrl.includes("github.com")) {
    return {
      status: "unavailable",
      source: group.fileUrl || group.file,
      lines: null,
      content: "",
      truncated: false,
      reason: "没有可读取的 GitHub 文件定位 URL。"
    };
  }

  const rawUrl = githubBlobToRawUrl(group.fileUrl, group.repository, group.file);
  if (!rawUrl) {
    return {
      status: "unavailable",
      source: group.fileUrl,
      lines: null,
      content: "",
      truncated: false,
      reason: "无法从 GitHub blob URL 解析 raw 文件地址。"
    };
  }

  const response = await fetch(rawUrl, {
    headers: { "User-Agent": "vulnerability-scanner" }
  });
  if (!response.ok) {
    return {
      status: "unavailable",
      source: rawUrl,
      lines: null,
      content: "",
      truncated: false,
      reason: `GitHub raw file returned ${response.status}.`
    };
  }

  const text = await response.text();
  const truncated = Buffer.byteLength(text, "utf8") > MAX_FILE_BYTES;
  const limited = truncated ? text.slice(0, MAX_FILE_BYTES) : text;
  const lineNumbers = group.findings.map((finding) => finding.line).filter(Number.isFinite);
  const selected = selectRelevantLines(limited, lineNumbers);

  return {
    status: "available",
    source: rawUrl,
    lines: selected.lines,
    content: redactSensitiveText(selected.content),
    // 本地研判需要整个文件（核验器要解析语法树）；只在 local-rag 时附带，只在内存里用，
    // 不写入 vault、不返回给前端，也绝不发给第三方 API
    ...(includeFullContent ? { fullContent: redactSensitiveText(limited) } : {}),
    truncated,
    redacted: true
  };
}

function githubBlobToRawUrl(fileUrl, repository, fullFile) {
  try {
    const url = new URL(fileUrl);
    const parts = url.pathname.split("/").filter(Boolean).map(decodeURIComponent);
    const blobIndex = parts.indexOf("blob");
    if (url.hostname !== "github.com" || blobIndex < 2) return null;

    const owner = parts[0];
    const repo = parts[1];
    const filePath = stripRepositoryPrefix(repository, fullFile);
    const fileParts = filePath.split("/").filter(Boolean);
    const afterBlob = parts.slice(blobIndex + 1);
    let suffixStart = afterBlob.length - fileParts.length;
    if (suffixStart < 1 || afterBlob.slice(suffixStart).join("/") !== fileParts.join("/")) {
      suffixStart = 1;
    }
    const branch = afterBlob.slice(0, suffixStart).join("/");
    const path = afterBlob.slice(suffixStart).join("/");
    if (!branch || !path) return null;
    return `https://raw.githubusercontent.com/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/${branch
      .split("/")
      .map(encodeURIComponent)
      .join("/")}/${path.split("/").map(encodeURIComponent).join("/")}`;
  } catch {
    return null;
  }
}

function stripRepositoryPrefix(repository, file) {
  const prefix = `${repository}/`;
  return String(file || "").startsWith(prefix) ? file.slice(prefix.length) : String(file || "");
}

function selectRelevantLines(text, lineNumbers) {
  const lines = text.split(/\r?\n/);
  if (!lineNumbers.length) {
    const max = Math.min(lines.length, 160);
    return {
      lines: max ? [1, max] : null,
      content: lines.slice(0, max).map((line, index) => `${index + 1}: ${line}`).join("\n")
    };
  }

  const center = Math.max(1, Math.min(...lineNumbers));
  const start = Math.max(1, center - Math.floor(CODE_WINDOW / 2));
  const end = Math.min(lines.length, start + CODE_WINDOW - 1);
  return {
    lines: [start, end],
    content: lines
      .slice(start - 1, end)
      .map((line, index) => `${start + index}: ${line}`)
      .join("\n")
  };
}

function redactSensitiveText(text) {
  return String(text || "")
    .replace(/\bgh[pousr]_[A-Za-z0-9_]{20,255}\b/g, "[REDACTED_GITHUB_TOKEN]")
    .replace(/\bgithub_pat_[A-Za-z0-9_]{22,255}\b/g, "[REDACTED_GITHUB_PAT]")
    .replace(/\bsk-(?:proj-)?[A-Za-z0-9_-]{20,255}\b/g, "[REDACTED_OPENAI_KEY]")
    .replace(/\b(?:A3T[A-Z0-9]|AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA)[A-Z0-9]{16}\b/g, "[REDACTED_AWS_ACCESS_KEY_ID]")
    .replace(/\bAIza[0-9A-Za-z_-]{20,45}\b/g, "[REDACTED_GOOGLE_API_KEY]")
    .replace(/\bxox[baprs]-[A-Za-z0-9-]{10,120}\b/g, "[REDACTED_SLACK_TOKEN]")
    .replace(/\bsk_(?:live|test)_[A-Za-z0-9]{16,255}\b/g, "[REDACTED_STRIPE_KEY]")
    .replace(/(secret|token|password|passwd|pwd|api[_-]?key|client[_-]?secret)\s*[:=]\s*["']?([A-Za-z0-9_./+=:@-]{12,200})["']?/gi, "$1=[REDACTED]");
}

async function requestAiAnalysis({ apiKey, provider, model, group, codeEvidence }) {
  if (provider === "local-rag") {
    return requestLocalRagAnalysis({ group, codeEvidence });
  }
  if (provider === "deepseek") {
    return requestChatCompletionsAnalysis({
      apiKey,
      model,
      endpoint: "https://api.deepseek.com/chat/completions",
      group,
      codeEvidence
    });
  }

  return requestOpenAiResponsesAnalysis({ apiKey, model, group, codeEvidence });
}

async function requestOpenAiResponsesAvailability({ apiKey, model }) {
  const response = await fetch("https://api.openai.com/v1/responses", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${apiKey}`,
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      model,
      input: [
        {
          role: "system",
          content: "Return a tiny JSON object only. All human-readable values must be Simplified Chinese."
        },
        {
          role: "user",
          content: "Return {\"ok\":true,\"message\":\"API 可用\"}."
        }
      ],
      text: {
        format: {
          type: "json_schema",
          name: "api_availability_check",
          strict: true,
          schema: {
            type: "object",
            additionalProperties: false,
            properties: {
              ok: { type: "boolean" },
              message: { type: "string" }
            },
            required: ["ok", "message"]
          }
        }
      }
    })
  });

  const payload = await response.json();
  if (!response.ok) {
    const error = new Error(payload.error?.message || `OpenAI API returned ${response.status}.`);
    error.status = response.status;
    throw error;
  }

  const parsed = JSON.parse(extractOutputText(payload));
  if (parsed.ok !== true) throw new Error("OpenAI API 响应成功，但可用性测试未返回 ok=true。");
}

async function requestChatCompletionsAvailability({ apiKey, model, endpoint }) {
  const response = await fetch(endpoint, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${apiKey}`,
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      model,
      messages: [
        {
          role: "system",
          content: "Return JSON only. All human-readable values must be Simplified Chinese."
        },
        {
          role: "user",
          content: "Return {\"ok\":true,\"message\":\"API 可用\"}."
        }
      ],
      response_format: { type: "json_object" },
      stream: false
    })
  });

  const payload = await response.json();
  if (!response.ok) {
    const error = new Error(payload.error?.message || `AI provider returned ${response.status}.`);
    error.status = response.status;
    throw error;
  }

  const content = payload.choices?.[0]?.message?.content;
  if (!content) throw new Error("AI provider response did not include message content.");
  const parsed = parseJsonObject(content);
  if (parsed.ok !== true) throw new Error("AI provider 响应成功，但可用性测试未返回 ok=true。");
}

async function requestOpenAiResponsesAnalysis({ apiKey, model, group, codeEvidence }) {
  const response = await fetch("https://api.openai.com/v1/responses", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${apiKey}`,
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      model,
      reasoning: { effort: "medium" },
      input: [
        {
          role: "system",
          content:
            "You are a defensive application security reviewer. Analyze only whether saved, already-discovered public code findings are plausibly exploitable. Do not provide exploit instructions, payloads, credential validation steps, or abuse workflows. Return concise remediation-focused JSON. All human-readable string values in the JSON must be Simplified Chinese."
        },
        {
          role: "user",
          content: JSON.stringify({
            task: "Deep exploitability analysis for a saved high-risk file.",
            constraints: [
              "所有返回字段中的自然语言内容必须使用简体中文。",
              "Do not validate or use leaked credentials.",
              "Do not give step-by-step attack instructions.",
              "Focus on exploitability preconditions, evidence, impact, false-positive signals, and remediation."
            ],
            file: group.file,
            repository: group.repository,
            fileUrl: group.fileUrl,
            findings: group.findings.map((finding) => ({
              key: finding.key,
              ruleId: finding.ruleId,
              label: finding.label,
              severity: finding.severity,
              stage: finding.stage,
              line: finding.line,
              context: finding.context,
              exploitability: finding.exploitability,
              verification: finding.verification
            })),
            codeEvidence
          })
        }
      ],
      text: {
        format: {
          type: "json_schema",
          name: "deep_security_analysis",
          strict: true,
          schema: {
            type: "object",
            additionalProperties: false,
            properties: {
              riskRating: { type: "string", enum: ["critical", "high", "medium", "low"] },
              exploitability: { type: "string", enum: ["confirmed_by_static_evidence", "plausible", "conditional", "unlikely"] },
              summary: { type: "string" },
              evidence: { type: "array", items: { type: "string" }, minItems: 1, maxItems: 8 },
              exploitPrerequisites: { type: "array", items: { type: "string" }, minItems: 1, maxItems: 8 },
              impact: { type: "array", items: { type: "string" }, minItems: 1, maxItems: 8 },
              falsePositiveSignals: { type: "array", items: { type: "string" }, maxItems: 8 },
              recommendedActions: { type: "array", items: { type: "string" }, minItems: 1, maxItems: 8 },
              safeValidationPlan: { type: "array", items: { type: "string" }, minItems: 1, maxItems: 8 }
            },
            required: [
              "riskRating",
              "exploitability",
              "summary",
              "evidence",
              "exploitPrerequisites",
              "impact",
              "falsePositiveSignals",
              "recommendedActions",
              "safeValidationPlan"
            ]
          }
        }
      }
    })
  });

  const payload = await response.json();
  if (!response.ok) {
    const error = new Error(payload.error?.message || `OpenAI API returned ${response.status}.`);
    error.status = response.status;
    throw error;
  }

  const outputText = extractOutputText(payload);
  return JSON.parse(outputText);
}

async function requestChatCompletionsAnalysis({ apiKey, model, endpoint, group, codeEvidence }) {
  const response = await fetch(endpoint, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${apiKey}`,
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      model,
      messages: [
        {
          role: "system",
          content:
            "You are a defensive application security reviewer. Analyze only whether saved, already-discovered public code findings are plausibly exploitable. Do not provide exploit instructions, payloads, credential validation steps, or abuse workflows. Return JSON only. All human-readable string values in the JSON must be Simplified Chinese."
        },
        {
          role: "user",
          content: `${JSON.stringify({
            task: "Deep exploitability analysis for a saved high-risk file.",
            requiredJsonShape: {
              riskRating: "critical|high|medium|low",
              exploitability: "confirmed_by_static_evidence|plausible|conditional|unlikely",
              summary: "string",
              evidence: ["string"],
              exploitPrerequisites: ["string"],
              impact: ["string"],
              falsePositiveSignals: ["string"],
              recommendedActions: ["string"],
              safeValidationPlan: ["string"]
            },
            constraints: [
              "所有返回字段中的自然语言内容必须使用简体中文。",
              "Do not validate or use leaked credentials.",
              "Do not give step-by-step attack instructions.",
              "Focus on exploitability preconditions, evidence, impact, false-positive signals, and remediation."
            ],
            file: group.file,
            repository: group.repository,
            fileUrl: group.fileUrl,
            findings: group.findings.map((finding) => ({
              key: finding.key,
              ruleId: finding.ruleId,
              label: finding.label,
              severity: finding.severity,
              stage: finding.stage,
              line: finding.line,
              context: finding.context,
              exploitability: finding.exploitability,
              verification: finding.verification
            })),
            codeEvidence
          })}`
        }
      ],
      response_format: { type: "json_object" },
      stream: false
    })
  });

  const payload = await response.json();
  if (!response.ok) {
    const error = new Error(payload.error?.message || `AI provider returned ${response.status}.`);
    error.status = response.status;
    throw error;
  }

  const content = payload.choices?.[0]?.message?.content;
  if (!content) throw new Error("AI provider response did not include message content.");
  return normalizeAnalysisResult(parseJsonObject(content));
}

const LOCAL_RAG_CWES = new Set(["CWE-78", "CWE-89", "CWE-22", "CWE-79"]);
const CLAIM_LABELS = {
  dead_branch: "传入用户输入的分支永远不会执行",
  key_mismatch: "从集合中取出的并不是用户输入",
  sanitizer: "用户输入在到达危险函数前经过了外部库编码",
  overwritten: "变量在到达危险函数前被重新赋值",
  param_query: "SQL 使用了参数化查询",
  no_taint: "危险函数不接收用户输入"
};

export async function requestLocalRagAnalysis({ group, codeEvidence }) {
  const code = codeEvidence.fullContent || "";
  const targets = group.findings.filter((finding) => LOCAL_RAG_CWES.has(finding.cwe));
  const decisions = [];
  for (const cwe of [...new Set(targets.map((finding) => finding.cwe))]) {
    // 扫描器报警的行号一起交给核验器：每一行都必须是核验器认识并检查过的危险函数
    const lines = targets.filter((finding) => finding.cwe === cwe).map((finding) => finding.line).filter(Number.isFinite);
    if (!code) {
      decisions.push({ cwe, decision: "review", by: "unavailable", reason: "无法读取文件内容" });
      continue;
    }
    try {
      const response = await fetch(`${RAG_TRIAGE_URL}/triage`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ cwe, file: group.file, code, lines }),
        signal: AbortSignal.timeout(Number(process.env.RAG_TRIAGE_TIMEOUT_MS || 180000))
      });
      if (!response.ok) throw new Error(`本地研判服务返回 ${response.status}`);
      decisions.push({ cwe, ...(await response.json()) });
    } catch (error) {
      // 研判失败只影响这一类告警，并且只能变成「人工复核」，绝不能变成「排除」
      decisions.push({ cwe, decision: "review", by: "error", reason: String(error?.message || error) });
    }
  }
  return summarizeLocalRag(group, decisions);
}

export function summarizeLocalRag(group, decisions) {
  const dismissed = decisions.filter((d) => d.decision === "dismissed");
  const kept = decisions.filter((d) => d.decision === "kept");
  // 只有文件里的全部告警都属于核验器支持的类型、且都被证明是误报，才能整体降级
  const unsupported = (group.findings || []).filter((finding) => !LOCAL_RAG_CWES.has(finding.cwe));
  const allDismissed = decisions.length > 0 && dismissed.length === decisions.length && unsupported.length === 0;
  const exploitability = allDismissed ? "unlikely" : kept.length ? "plausible" : "conditional";
  const signals = dismissed.map((d) => {
    const claim = d.verified_claim;
    return claim && ["dead_branch", "key_mismatch", "sanitizer"].includes(claim.type)
      ? `${d.cwe}：第 ${claim.line} 行 —— ${CLAIM_LABELS[claim.type]}（已由核验器确认）`
      : `${d.cwe}：程序分析确认危险函数不接收用户输入（已由核验器确认）`;
  });
  const result = normalizeAnalysisResult({
    riskRating: allDismissed ? "low" : group.severity,
    exploitability,
    summary: allDismissed
      ? "所有相关告警都被核验器证明为误报。"
      : kept.length
        ? "本地模型认为存在可被利用的数据流，且没有任何理由能证明安全，保留告警。"
        : unsupported.length && dismissed.length === decisions.length && decisions.length
          ? "核验器支持的告警已被证明为误报，但文件中还有其它类型的告警，保留原有风险等级。"
          : "没有能被核验的误报理由，交给人工复核。",
    evidence: decisions.map((d) => `${d.cwe}：${d.decision}（${d.by || "-"}）${d.reason ? " —— " + d.reason : ""}`),
    falsePositiveSignals: signals,
    recommendedActions: allDismissed ? ["抽查核验器给出的理由即可。"] : ["按告警位置人工确认数据流，并参考对应 CWE 的修复建议。"]
  });
  return { ...result, localRag: { decisions } };
}

function parseJsonObject(content) {
  const trimmed = String(content || "").trim();
  const unfenced = trimmed.replace(/^```(?:json)?\s*/i, "").replace(/\s*```$/i, "");
  return JSON.parse(unfenced);
}

function normalizeAnalysisResult(result) {
  return {
    riskRating: normalizeEnum(result.riskRating, ["critical", "high", "medium", "low"], "medium"),
    exploitability: normalizeEnum(
      result.exploitability,
      ["confirmed_by_static_evidence", "plausible", "conditional", "unlikely"],
      "conditional"
    ),
    summary: String(result.summary || "AI 分析未返回摘要。"),
    evidence: normalizeStringArray(result.evidence, ["AI 分析未返回证据。"]),
    exploitPrerequisites: normalizeStringArray(result.exploitPrerequisites, ["需要人工复核利用前提。"]),
    impact: normalizeStringArray(result.impact, ["需要人工复核影响范围。"]),
    falsePositiveSignals: normalizeStringArray(result.falsePositiveSignals, []),
    recommendedActions: normalizeStringArray(result.recommendedActions, ["复核文件内容并轮换可能泄露的凭证。"]),
    safeValidationPlan: normalizeStringArray(result.safeValidationPlan, ["仅使用自有账户和自有凭证做验证。"])
  };
}

function normalizeEnum(value, allowed, fallback) {
  return allowed.includes(value) ? value : fallback;
}

function normalizeStringArray(value, fallback) {
  if (!Array.isArray(value)) return fallback;
  const normalized = value.map((item) => String(item || "").trim()).filter(Boolean);
  return normalized.length ? normalized.slice(0, 8) : fallback;
}

function extractOutputText(payload) {
  if (payload.output_text) return payload.output_text;
  const text = payload.output
    ?.flatMap((item) => item.content || [])
    .filter((content) => content.type === "output_text" || content.type === "text")
    .map((content) => content.text)
    .join("");
  if (!text) throw new Error("OpenAI response did not include output text.");
  return text;
}

function resolveAiProvider({ apiKey, model, provider = "openai" } = {}) {
  const resolvedProvider = providerConfigs[provider] ? provider : "openai";
  const providerConfig = providerConfigs[resolvedProvider];
  const resolvedModel = model || providerConfig.defaultModel;
  const resolvedApiKey = apiKey || firstEnvValue(providerConfig.envKeys);
  if (providerConfig.keyless) {
    return { providerConfig, resolvedModel, resolvedProvider, resolvedApiKey: "" };
  }
  if (!resolvedApiKey) {
    const error = new Error(
      `请提供 ${providerConfig.label} API Key，或在 Vercel 环境变量配置 ${providerConfig.envKeys.join(" / ")}。`
    );
    error.status = 400;
    throw error;
  }

  return { providerConfig, resolvedModel, resolvedProvider, resolvedApiKey };
}

function firstEnvValue(names) {
  return names.map((name) => process.env[name]).find(Boolean);
}

function higherSeverity(left, right) {
  return severityRank(right) > severityRank(left) ? right : left;
}

function severityRank(severity) {
  return {
    low: 1,
    medium: 2,
    high: 3,
    critical: 4
  }[severity] || 0;
}

function fingerprint(value) {
  let hash = 2166136261;
  for (let index = 0; index < String(value).length; index += 1) {
    hash ^= String(value).charCodeAt(index);
    hash = Math.imul(hash, 16777619);
  }
  return (hash >>> 0).toString(16);
}
