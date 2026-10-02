# ContextAudit

ContextAudit 是一个面向函数级漏洞分析的三阶段大语言模型流水线，用来比较“仅观察修复前代码”和“同时观察修复前后代码及补丁信息”两种上下文条件下的分析结果，并据此计算上下文依赖分数（Context Dependency Score, CDS）。

项目支持 OpenAI 兼容的 Chat Completions 接口、多进程执行、阶段级容错、错误样本补跑、结果重建以及多种公开漏洞数据集的输入转换。仓库只包含代码、测试和小型示例，不包含论文实验输出、模型响应、真实数据集或 API 密钥。

## 工作流程

对每个函数对依次执行三个阶段：

1. **阶段 A（盲测分析）**：输入已知 CWE 与修复前函数，识别外部调用、数据流路径、漏洞变量、位置、置信度和所需额外上下文。
2. **阶段 B（参考分析）**：输入 CWE、修复前后函数、提交信息与漏洞描述，生成包含补丁证据的参考报告。
3. **阶段 C（证据裁判）**：只比较 A、B 两份报告明确写出的证据，分别给出变量/实体、步骤位置和数据流路径的一致性得分及理由。

阶段 C 的三个分数为 `0`、`0.25`、`0.5`、`0.75` 或 `1`。代码侧只要求它们是有限数值，不额外强制离散取值，以免丢失兼容接口已经生成的有效结果。

综合一致性与 CDS 的定义为：

```text
similarity = 0.5 * ((E + L + F) / 3 + min(E, L, F))
CDS        = 1 - similarity
```

其中 `E`、`L`、`F` 分别对应变量/实体、步骤位置和数据流路径得分。CDS 越高，表示分析结果越依赖补丁及其上下文。

## 项目结构

```text
ContextAudit/
├── src/three_stage_pipeline/   # 流水线、提示词、输入输出、API 客户端
├── scripts/                    # 数据转换、结果重建、CDS 统计和补跑入口
│   └── analysis/               # 原三模型实验的汇总脚本
├── tests/                      # 无网络单元测试
├── examples/                   # 最小 JSON 输入与示例 C 代码
├── input/README.md             # 输入数据格式说明（不包含数据集）
├── .env.example                # 环境变量名称示例（不含密钥）
└── pyproject.toml              # Python 包与命令行入口
```

## 安装

需要 Python 3.10 或更高版本。建议在独立虚拟环境中安装：

```powershell
git clone <your-repository-url> ContextAudit
cd ContextAudit
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -e .
```

Linux/macOS 激活环境时使用：

```bash
source .venv/bin/activate
```

如需直接读取 Parquet，再安装可选依赖：

```bash
python -m pip install -e ".[parquet]"
```

安装后提供以下命令：

- `context-audit`：运行流水线；
- `context-audit-rerun`：按错误日志补跑；
- `three-stage-pipeline`、`three-stage-rerun-errors`：为旧脚本保留的兼容别名。

## 配置模型

流水线调用 OpenAI 兼容接口，需要三个环境变量：

| 变量 | 含义 |
|---|---|
| `LLM_API_KEY` | API 密钥 |
| `LLM_BASE_URL` | 兼容接口的基础 URL，通常以 `/v1` 结尾 |
| `LLM_MODEL` | 接口接受的模型名称 |

PowerShell 示例：

```powershell
$env:LLM_API_KEY = "replace-with-your-api-key"
$env:LLM_BASE_URL = "https://api.example.com/v1"
$env:LLM_MODEL = "your-model-name"
```

Bash 示例：

```bash
export LLM_API_KEY="replace-with-your-api-key"
export LLM_BASE_URL="https://api.example.com/v1"
export LLM_MODEL="your-model-name"
```

`.env.example` 只用于说明变量名称；当前程序不会自动读取 `.env` 文件。请通过系统环境、Shell、CI Secrets 或密钥管理服务注入配置，不要把真实密钥提交到 Git。

## 输入格式

命令接受 CSV、JSON、JSONL 或 Parquet，也可以传入只包含一个可识别输入文件的目录。推荐 CSV 至少包含：

| 字段 | 必需 | 说明 |
|---|---:|---|
| `sample_id` | 是 | 唯一样本 ID，同时用于输出文件名 |
| `func_before` | 是 | 修复前函数 |
| `func_after` | 是 | 修复后函数 |
| `cwe` | 建议 | 已知漏洞类型 |
| `commit_id` | 否 | 修复提交 ID |
| `project` | 否 | 项目名 |
| `commit_msg` / `commit_msg_anonymized` | 否 | 提交信息；优先匿名字段 |
| `bug_description` / `bug_description_anonymized` | 否 | 漏洞描述；优先匿名字段 |

JSON 最小示例见 [`examples/sample.json`](examples/sample.json)。真实数据集没有随仓库分发，请遵守各数据集的许可和访问条款。

## 运行流水线

默认只处理第 1 条，避免误触发大批量付费调用：

```powershell
context-audit .\examples\sample.json --start 1 --end 1 --output-dir .\output
```

处理 CSV 的前 1000 条，并使用 4 个工作进程：

```powershell
context-audit .\input\dataset.csv `
  --start 1 `
  --end 1000 `
  --workers 4 `
  --output-dir .\output
```

`--start` 和 `--end` 均为从 1 开始且包含端点。每个工作进程独立调用模型；主进程按输入顺序写结果，因此不会并发抢写 CSV。请根据接口的并发限制、速率限制和超时情况调整 `--workers`。

## 输出与容错

每个样本会得到同名的阶段文件和汇总文件：

```text
output/
├── phase_a/<sample_id>.json
├── phase_b/<sample_id>.json
├── phase_c/<sample_id>.json
├── combined/<sample_id>.json
├── final_results.csv
└── pipeline_errors.jsonl
```

`final_results.csv` 固定包含样本元数据、三个阶段的结构化字段和三个原始 JSON 报告，共 26 列。以相同 `sample_id` 重跑会更新原记录，而不是追加重复行。

任一阶段遇到请求失败、非法 JSON 或字段校验失败时，程序会：

- 输出包含样本、阶段和重试详情的警告；
- 写入结构兼容的占位结果；
- 继续后续阶段和其他样本；
- 将问题统一记录到 `pipeline_errors.jsonl`。

补跑错误样本：

```powershell
context-audit-rerun `
  .\output\pipeline_errors.jsonl `
  .\input\dataset.csv `
  --workers 2 `
  --output-dir .\output
```

补跑会对选中的样本重新执行完整 A/B/C 流水线；本轮仍失败的记录写入 `pipeline_errors_rerun.jsonl`。

如果阶段 JSON 已存在，可从 `combined` 重新构建最终 CSV：

```powershell
python .\scripts\build_final_csv.py .\output\combined `
  --output .\output\final_results_from_combined.csv
```

## 计算 CDS 与分布

```powershell
python .\scripts\calculate_cds.py .\output\final_results.csv
```

默认生成：

- `final_results_with_cds.csv`：新增或更新 `similarity`、`cds_score` 和 `cds_band`；
- `final_results_cds_distribution.csv`：按 0.1 宽度统计 CDS 的数量与百分比。

包含占位符、空值、非数值或非有限分数的行会被跳过，并计入脚本输出的跳过数量。`calculate_similarity.py` 是为旧调用保留的兼容入口，执行相同的 CDS 计算。

## 数据转换工具

`scripts/` 中包含以下独立工具：

| 脚本 | 用途 |
|---|---|
| `convert_parquet_to_csv.py` | 将 Parquet 转为 UTF-8 CSV |
| `convert_megavul_to_csv.py` | 将 MegaVul 漏洞函数对转换为统一 CSV，并按长度阈值筛选 |
| `convert_reposvul_to_csv.py` | 合并 ReposVul JSONL，并从公开修复提交重建 before/after 函数对 |
| `convert_paired_csv_to_pipeline.py` | 转换 TitanVul、BenchVul 和 vulnerability-score CSV |
| `prepare_deduplicated_vulnerability_datasets.py` | 配对 PrimeVul，并对多数据集做全局去重 |
| `filter_oversized_csv_rows.py` | 排除字段超长的 CSV 行并记录原因 |
| `analyze_code_lengths.py` | 统计函数与 diff 的字符数、行数和分位数 |

查看具体参数：

```bash
python scripts/convert_megavul_to_csv.py --help
```

ReposVul 转换需要访问 GitHub 原始文件服务；核心流水线和单元测试本身不依赖该网络请求。

## 测试

测试使用本地假模型，不会调用外部 API：

```powershell
$env:PYTHONPATH = (Resolve-Path .\src).Path
python -m unittest discover -s tests -v
```

Bash：

```bash
PYTHONPATH=src python -m unittest discover -s tests -v
```

## 提示词与可复现性

三个阶段的完整提示词位于 `src/three_stage_pipeline/prompts.py`。接口参数、JSON 提取与重试逻辑位于 `client.py`，阶段输出约束位于 `contracts.py`。为复现实验，请同时记录模型名称、接口提供方、运行日期、并发数和输入数据版本；不同兼容服务可能对 `response_format`、`extra_body` 或思考模式参数有不同支持。

## 发布前说明

- 本仓库副本没有包含任何实验输出、原始数据集、虚拟环境、缓存或真实密钥。
- 请在公开发布前选择并添加合适的开源许可证；代码未附许可证时，其他人默认没有复制、修改和再分发权利。
- 如果项目曾在其他文件或历史记录中保存过真实密钥，应先撤销并轮换密钥，再创建公开仓库。
