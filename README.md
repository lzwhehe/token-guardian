# 漏洞扫描器

一个面向 GitHub 和本地仓库的静态漏洞扫描器。它会根据当前文件内容匹配可能存在的凭证泄露、依赖 CVE、CWE 风险代码模式和常见安全配置问题，并把结果按仓库、文件、规则、严重级别聚合展示。

## 功能

- 扫描当前文件中的常见密钥格式：GitHub、OpenAI、Anthropic、DeepSeek、Hugging Face、Replicate、Groq、Pinecone、LangSmith、AWS、Google、Azure、Slack、Stripe、Discord、Telegram、Twilio、GitLab、npm、PyPI、Docker Hub、Datadog、Sentry、Notion、Airtable、Stripe、PayPal、Supabase、MongoDB、Redis、数据库连接串、JWT、私钥等。
- 根据文件内容匹配可能 CVE/CWE 风险：Log4Shell、Spring4Shell、Fastjson 反序列化、lodash/minimist 原型污染，以及命令注入、SQL 注入、路径穿越、SSRF、XSS、不安全反序列化、过宽 CORS 等静态漏洞模式。
- 线上模式支持输入 GitHub 用户/组织主页，例如 `https://github.com/lzwhehe`，自动枚举最近更新的仓库并搜索风险文件。
- 扫描流程按阶段执行并返回聚合结果：风险文件名、token pattern、entropy/context、漏洞/CVE 规则、可插拔 validity check。
- 可选扫描 Git 历史补丁，发现曾经提交过又删除的 secret。
- 对疑似 `KEY=value` 形式的高熵字符串做启发式检测。
- 结果只返回脱敏片段；凭证类命中不会在前端显示完整 token。

## 运行

```bash
npm install
npm run dev
```

打开 Vite 输出的本地地址。默认后端 API 运行在 `http://localhost:8787`。

## 命令行扫描

```bash
npm run scan -- /path/to/repo --history
npm run scan -- https://github.com/owner/repo.git
```

线上 Vercel API 默认使用 GitHub API 模式，支持：

- `github:explore`
- `https://github.com`
- `https://github.com/owner`
- `https://github.com/org`
- `https://github.com/owner/repo`
- `owner/repo`

探索模式会用 GitHub public repository search 自主发现最近活跃的 AI 相关公开仓库，优先覆盖 `artificial-intelligence`、`machine-learning`、`llm`、`large-language-models`、`generative-ai`、`rag`、`ai-agent`、`langchain`、`openai`、`deepseek`、`huggingface`、`vector-database` 等 topic 和关键词查询，再按风险优先级扫描风险文件和可扫描源码文件。排序会优先选择低 star、小体量、最近活跃、demo/starter/tutorial 类型的 AI 项目，因为这类项目更容易出现真实凭证或 `.env` 误提交。它不是一次性全量扫完整个 GitHub，而是适合在 API 限制内按批次持续探索。

线上默认探索 60 个仓库、每仓库最多 80 个候选文件；页面上仓库上限可调到 500。建议配置 `GITHUB_TOKEN`，否则 GitHub 未认证 API 速率限制会明显影响覆盖量。

扫描结果会返回并展示已扫描仓库列表，包括仓库名、描述、语言、star 数、扫描文件数和跳过状态。

如果检测到真实 token、疑似 secret、密码型连接串、私钥内容或可定位的高危漏洞模式，后端会返回 `riskProjects`，前端会自动把对应项目收纳到“风险项目收纳”列表，并保存在浏览器本地存储中。风险文件名现在只作为候选扫描信号，不会单独把项目判定为高危。GitHub 扫描命中会附带 `fileUrl`，前端可以直接定位到问题文件或具体行号。

每条命中还会给出 `exploitability` 评估：根据泄漏文件类型、token 规则、上下文、熵值、CVE/CWE 映射和危险 API 模式列出可能利用模式、利用前提、置信度和非侵入式安全测试证据。默认不会调用第三方 API 验证他人 token，也不会对目标项目发起漏洞利用 payload。

## 规则来源

内置规则包含项目自研规则、CVE/CWE 静态漏洞规则，以及参考 [Coff0xc/Github-API-scan](https://github.com/Coff0xc/Github-API-scan) 的纯匹配规则整理。该项目使用 MIT License；本项目只吸收 regex/search matching 思路，不吸收 token 验证、余额查询或权限探测逻辑。扫描结果会给命中项标注 `provider`、`category`、`cwe`、`possibleCves`、`evidenceLevel` 和 `sourceRuleSet`，便于区分精确格式、上下文格式、泛高熵命中和静态漏洞模式。

## 漏洞持久化

扫描 API 会把脱敏后的风险项目、漏洞命中、定位 URL、利用模式评估和扫描摘要写入漏洞仓库。线上优先使用 Vercel Blob 的私有对象 `token-guardian/vulnerability-vault.json`，本地开发会回退到 `.scanner-data/vault.json`。

可用接口：

- `GET /api/vault`：读取已保存的漏洞仓库
- `DELETE /api/vault`：清空漏洞仓库

如果线上没有配置 Vercel Blob，扫描仍会正常运行，但页面会显示“未配置持久化”。在 Vercel 项目中添加 Blob 存储后，`BLOB_READ_WRITE_TOKEN` 会自动注入，重新部署即可跨会话、跨部署保存结果。

## 高风险文件与 AI 深度分析

“高风险文件”页面会单独列出已持久化漏洞仓库中具备内容证据的高风险文件，包括严重/高危 token pattern、高熵 secret、密码型连接串、私钥内容、依赖 CVE 和高危代码漏洞模式。仅命中文件名的候选风险会保留在扫描结果和流水线聚合里，但不会进入高风险页或风险项目收纳。

点击“深度分析”会调用 `POST /api/analyze`，读取已保存的 GitHub 文件定位，抓取有限的公开代码上下文，并在发送给 AI 前做脱敏。当前支持 OpenAI 和 DeepSeek 两种 provider。API Key 有两种方式：

- 在页面临时输入 OpenAI / DeepSeek API Key：只随本次请求发送，不写入 vault。
- 在 Vercel 环境变量配置 `OPENAI_API_KEY`、`AI_SECURITY_API_KEY`、`DEEPSEEK_API_KEY` 或 `AI_SECURITY_DEEPSEEK_API_KEY`。

“API可用性测试”只会调用当前选择的 AI provider 和模型做一次最小化健康检查，不读取漏洞文件，也不保存 API Key。

AI 分析结果会保存回漏洞仓库，包含静态证据、可利用前提、影响、误报信号、安全验证计划和修复建议。分析不会验证或使用泄露凭证。

私有仓库需要在 Vercel 项目环境变量里配置 `GITHUB_TOKEN`。

## 本地研判：大模型提理由，核验器下结论（`local-rag`）

云端大模型「裸判」有两个问题：代码要发到外部；而且被扫描的仓库由攻击者控制，代码注释里一句「已通过安全审查」就可能让模型把真漏洞判成误报。`local-rag` 改成全部在本地运行，并且**把判定权交给确定性核验器**：

1. **程序分析**（`rag/verifier.py`）：先跑一遍保守的污点分析。如果能直接证明危险函数不接收用户输入，就判为误报。
2. **本地大模型**（vLLM 部署的 Qwen3-8B）：读代码，指出「可能是误报」的位置，最多 3 处。比如「第 27 行的分支永远不会执行」「第 32 行从列表里取出的不是用户输入」。
3. **核验器**：在 Java 语法树上逐项检查模型指出的理由：常量折叠、精确模拟集合内容、外部编码函数白名单。**只有核验通过，告警才会被排除**；否则模型的意见只用来决定「保留」还是「交给人工复核」。

在 OWASP Benchmark（混淆版，测试集 1,183 条）上的结果，详见 [docs/RAG_EVAL.md](docs/RAG_EVAL.md)：

| 方案 | 误报排除 | 真漏洞被误排除 |
|---|---|---|
| 只用程序分析 | 11.2% | 0 |
| **大模型 + 核验（本方案）** | **56.7%** | **0 / 622** |
| 大模型单独判断（不核验） | 74.0% | 17 / 622 |
| 加入知识检索（RAG），不核验 | 68.6% | 31 / 622 |

- **知识检索没有带来提升**：在统计上与「塞入等长的随机知识」没有区别（配对 McNemar 检验 p = 0.08 / 0.85），所以最终方案不用它。
- **完整系统在 7 类攻击下一次都没被骗**；而大模型单独判断时，被自适应注入骗过 40%，被 3 条伪造知识投毒骗过 71%。
- **「0 个真漏洞被误排除」是在 Benchmark 上测得的**。核验器 v1 曾被代码审查手写的 25 个真实漏洞骗过 23 次；v2 改为「看不懂就拒绝」后全部挡住，这 25 个用例也已加入回归测试。
- **评测全部使用混淆版代码**：原版 Benchmark 里的命名和字符串常量会暗示答案，用原版会让模型的成绩虚高一倍多。

运行方式：

```bash
# 1. 本地部署模型（OpenAI 兼容接口）
vllm serve Qwen/Qwen3-8B --quantization fp8 --port 8011
# 2. 启动研判服务（只依赖标准库 + javalang）
pip install javalang && RAG_LLM_BASE_URL=http://127.0.0.1:8011/v1 python rag/service.py --port 8790
# 3. 扫描器里选择 provider = local-rag（或设置 RAG_TRIAGE_URL）
```

复现评测：`rag/bench_prep.py` → `rag/run_eval.py` → `rag/score.py` → `rag/report.py`。Benchmark 是 GPL-2.0，用例只在本地评测，不随本仓库分发。设计和取舍记录在 [docs/RAG_DESIGN.md](docs/RAG_DESIGN.md) 和 [docs/DECISIONS.md](docs/DECISIONS.md)。

> 核验器目前只支持 Java 的命令注入 / SQL 注入 / 路径遍历 / XSS，其它语言和类型的告警一律交给人工复核，不会做未经核验的排除。仅用于授权的安全测试与代码审计。

当前 validity check 默认关闭，避免对第三方 token 发起验证请求。后续如果只验证你自己服务的 token，可以为对应 provider 单独接入安全验证器。

## 重要提醒

如果确认已经泄露 token，请立即到对应平台撤销/轮换。删除提交记录并不能让已经泄露的凭证重新安全。
