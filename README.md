>[!NOTE]
> **[📢 New: Shanom is now available via `npx shanom`. →](https://github.com/JonusNattapong/shanom/discussions/249)**

<div align="center">

<img src="./assets/github-banner.png" alt="Shanom — AI Pentester for Web Applications and APIs" width="100%">

# Shanom — AI Pentester

<a href="https://trendshift.io/repositories/15604" target="_blank"><img src="https://trendshift.io/api/badge/repositories/15604" alt="JonusNattapong%2Fshanom | Trendshift" style="width: 250px; height: 55px;" width="250" height="55"/></a>

Shanom is an autonomous, white-box AI pentester for web applications and APIs. <br />
It analyzes your source code, identifies attack vectors, and executes real exploits to prove vulnerabilities before they reach production.

---

<a href="https://discord.gg/9ZqQPuhJB7"><img src="./assets/discord.png" height="40" alt="Join Discord"></a>

---
</div>

## What is Shanom?

Shanom is an AI pentester. It performs white-box security testing of web applications and their underlying APIs by combining source code analysis with live exploitation.

Shanom analyzes your web application's source code to identify potential attack vectors, then uses browser automation and command-line tools to execute real exploits (injection attacks, authentication bypass, SSRF, XSS) against the running application and its APIs. Only vulnerabilities with a working proof-of-concept are included in the final report.

**Why Shanom Exists**

Thanks to tools like Claude Code and Cursor, your team ships code non-stop. But your penetration test? That happens once a year. This creates a *massive* security gap. For the other 364 days, you could be unknowingly shipping vulnerabilities to production.

Shanom closes that gap by providing on-demand, automated penetration testing that can run against every build or release.

## Shanom in Action

Shanom identified 20+ vulnerabilities in OWASP Juice Shop, including authentication bypass and database exfiltration. [Full report →](sample-reports/shanom-report-juice-shop.md)

![Demo](assets/shanom-action.gif)

## Features

- **Fully Autonomous Operation**: A single command launches the full pentest. Shanom handles 2FA/TOTP logins (including SSO), browser navigation, exploitation, and report generation without manual intervention.
- **Reproducible Proof-of-Concept Exploits**: The final report contains only proven, exploitable findings with copy-and-paste PoCs. Vulnerabilities that cannot be exploited are not reported.
- **OWASP Vulnerability Coverage**: Identifies and validates Injection, XSS, SSRF, and Broken Authentication/Authorization, with additional categories in development.
- **Code-Aware Dynamic Testing**: Analyzes source code to guide attack strategy, then validates findings with live browser and CLI-based exploits against the running application.
- **CPG Engine with LLM Reasoning**: Shanom Pro transforms your codebase into a Code Property Graph (CPG) combining AST, CFG, and PDG. At every node, an LLM evaluates security properties and data flow paths from sources to sinks.
- **Static Analysis (SAST)**: Detects point vulnerabilities including weak cryptography, hardcoded credentials, insecure configuration, missing security headers, and weak random number generation.
- **SCA with Reachability Analysis**: Identifies vulnerable dependencies and traces whether vulnerable functions are actually reachable from your code's entry points.
- **Secrets Detection**: Combines regex pattern matching, LLM-based detection for custom formats, and entropy analysis to find exposed credentials.
- **Static-Dynamic Correlation**: Validates static findings with dynamic exploits. Every reported vulnerability has both a code location and a working proof-of-concept.
- **Enhanced Reporting**: Generate technical pentest reports, remediation guidance with prioritized fix instructions, and executive/board-level summaries.
- **Integrated Security Tooling**: Leverages Nmap, Subfinder, WhatWeb, and Schemathesis during reconnaissance and discovery phases.
- **Parallel Processing**: Vulnerability analysis and exploitation phases run concurrently across all attack categories.

## Product Line

Shanom is available in two editions:

| Edition | License | Best For |
|---------|---------|----------|
| **Shanom Lite** | AGPL-3.0 | Local testing of your own applications. |
| **Shanom Pro** | Commercial | Organizations needing a single AppSec platform (SAST, SCA, secrets, business logic testing, autonomous pentesting) with CI/CD integration and self-hosted deployment. |

> **This repository contains Shanom Lite,** the core autonomous AI pentesting framework. **Shanom Pro** is Keygraph's all-in-one AppSec platform, combining SAST, SCA, secrets scanning, business logic security testing, and autonomous AI pentesting in a single correlated workflow. Every finding is validated with a working proof-of-concept exploit.

> [!IMPORTANT]
> **White-box only.** Shanom Lite is designed for **white-box (source-available)** application security testing.  
> It expects access to your application's source code and repository layout.

### Shanom Pro: Architecture Overview

Shanom Pro is an all-in-one application security platform that replaces the need to stitch together separate SAST, SCA, secrets scanning, and pentesting tools. It operates as a two-stage pipeline: agentic static analysis of the codebase, followed by autonomous AI penetration testing. Findings from both stages are cross-referenced and correlated, so every reported vulnerability has a working proof-of-concept exploit and a precise source code location.

**Stage 1: Agentic Static Analysis**

Shanom Pro transforms the codebase into a Code Property Graph (CPG) combining the AST, control flow graph, and program dependence graph. It then runs five analysis capabilities:

- **Data Flow Analysis (SAST)**: Identifies sources (user input, API requests) and sinks (SQL queries, command execution), then traces paths between them. At each node, an LLM evaluates whether the specific sanitization applied is sufficient for the specific vulnerability in context, rather than relying on a hard-coded allowlist of safe functions.
- **Point Issue Detection (SAST)**: LLM-based detection of single-location vulnerabilities: weak cryptography, hardcoded credentials, insecure configuration, missing security headers, weak RNG, disabled certificate validation, and overly permissive CORS.
- **Business Logic Security Testing (SAST)**: LLM agents analyze the codebase to discover application-specific invariants (e.g., "document access must verify organizational ownership"), generate targeted fuzzers to violate those invariants, and synthesize full PoC exploits. This catches authorization failures and domain-specific logic errors that pattern-based scanners cannot detect.
- **SCA with Reachability Analysis**: Goes beyond flagging CVEs by tracing whether the vulnerable function is actually reachable from application entry points via the CPG. Unreachable vulnerabilities are deprioritized.
- **Secrets Detection**: Combines regex pattern matching with LLM-based detection (for dynamically constructed credentials, custom formats, obfuscated tokens) and performs liveness validation against the corresponding service using read-only API calls.

**Stage 2: Autonomous Dynamic Penetration Testing**

The same multi-agent pentest pipeline as Shanom Lite (reconnaissance, parallel vulnerability analysis, parallel exploitation, reporting), enhanced with static findings injected into the exploitation queue. Static findings are mapped to Shanom's five attack domains (Injection, XSS, SSRF, Auth, Authz), and exploit agents attempt real proof-of-concept attacks against the running application for each finding.

**Static-Dynamic Correlation**

This is the core differentiator. A data flow vulnerability identified in static analysis (e.g., unsanitized input reaching a SQL query) is not reported as a theoretical risk. It is fed to the corresponding exploit agent, which attempts to exploit it against the live application. Confirmed exploits are traced back to the exact source code location, giving developers both proof of exploitability and the line of code to fix.

**Deployment Model**

Shanom Pro supports a self-hosted runner model (similar to GitHub Actions self-hosted runners). The data plane, which handles code access and all LLM API calls, runs entirely within the customer's infrastructure using the customer's own API keys. Source code never leaves the customer's network. The Keygraph control plane handles job orchestration, scan scheduling, and the reporting UI, receiving only aggregate findings.

| Capability | Shanom Lite | Shanom Pro (All-in-One AppSec) |
| --- | --- | --- |
| **Licensing** | AGPL-3.0 | Commercial |
| **Static Analysis** | CPG-based SAST, SCA, secrets scanning | Full agentic analysis with enhanced coverage |
| **Dynamic Testing** | Autonomous AI pentesting | Autonomous AI pentesting with static-dynamic correlation |
| **Analysis Engine** | CPG with LLM reasoning at every node | Enhanced CPG with business logic testing |
| **SAST Coverage** | Data flow, point issues, crypto, secrets | + Business logic security testing |
| **SCA** | Reachability analysis | + License compliance, SBOM generation |
| **CI/CD Integration** | CLI-based | Native CI/CD, GitHub PR scanning, quality gates |
| **Reporting** | Technical, Remediation, Board reports | + Custom dashboards, scheduled reports |
| **Deployment** | Local CLI | Managed cloud or self-hosted runner |
| **Multi-Tenancy** | Single user/org | Enterprise multi-tenancy with RBAC |

[Full technical details →](./SHANNON-PRO.md)

## Table of Contents

- [What is Shanom?](#what-is-shanom)
- [Shanom in Action](#shanom-in-action)
- [Features](#features)
- [Product Line](#product-line)
- [Setup & Usage Instructions](#setup--usage-instructions)
  - [Prerequisites](#prerequisites)
  - [Quick Start (Recommended: npx)](#quick-start-recommended-npx)
  - [Clone and Build](#clone-and-build)
  - [Prepare Your Repository](#prepare-your-repository)
  - [Common Commands](#common-commands)
  - [Workspaces and Resuming](#workspaces-and-resuming)
  - [Credentials and Configuration](#credentials-and-configuration)
  - [AWS Bedrock](#aws-bedrock)
  - [Google Vertex AI](#google-vertex-ai)
  - [Custom Base URL](#custom-base-url)
  - [Router Mode](#experimental---unsupported-router-mode-alternative-providers)
  - [Platform-Specific Instructions](#platform-specific-instructions)
  - [Output and Results](#output-and-results)
- [Sample Reports](#sample-reports)
- [Benchmark](#benchmark)
- [Architecture](#architecture)
- [Coverage and Roadmap](#coverage-and-roadmap)
- [Disclaimers](#disclaimers)
- [License](#license)
- [Community & Support](#community--support)
- [Get in Touch](#get-in-touch)

---

## Setup & Usage Instructions

### Prerequisites

- **Docker** - Container runtime ([Install Docker](https://docs.docker.com/get-docker/))
- **Node.js 18+** - Required for `npx` usage ([Install Node.js](https://nodejs.org/))
- **pnpm** - Required for Clone and Build mode ([Install pnpm](https://pnpm.io/installation))
- **AI Provider Credentials** (choose one):
  - **Anthropic API key** (recommended) - Get from [Anthropic Console](https://console.anthropic.com)
  - **Claude Code OAuth token**
  - **AWS Bedrock** - Route through Amazon Bedrock with AWS credentials (see [AWS Bedrock](#aws-bedrock))
  - **Google Vertex AI** - Route through Google Cloud Vertex AI (see [Google Vertex AI](#google-vertex-ai))
  - **[EXPERIMENTAL - UNSUPPORTED] Alternative providers via Router Mode** - OpenAI or Google Gemini via OpenRouter (see [Router Mode](#experimental---unsupported-router-mode-alternative-providers))

> [!NOTE]
> Docker is still required to use the `npx` workflow. Under the hood, the CLI pulls and runs a prebuilt Shanom worker image from Docker Hub, which is approximately 1 GB and contains Shanom plus all required dependencies.

### Quick Start (Recommended: npx)

```bash
# 1. Configure credentials (interactive wizard — one-time setup)
npx @keygraph/shanom setup

# Or export env vars directly
export ANTHROPIC_API_KEY=your-api-key

# 2. Run a pentest
npx @keygraph/shanom start -u https://your-app.com -r /path/to/your-repo
```

Shanom will pull the worker image from Docker Hub, start the infrastructure, and launch an ephemeral worker container for the scan.

### Clone and Build

Use this if you want to run Shanom from a local clone, modify Shanom itself, or keep the worker image built locally.

```bash
# 1. Clone Shanom
git clone https://github.com/JonusNattapong/shanom.git
cd shanom

# 2. Configure credentials (choose one method)

# Option A: Create a .env file
cat > .env << 'EOF'
ANTHROPIC_API_KEY=your-api-key
CLAUDE_CODE_MAX_OUTPUT_TOKENS=64000
EOF

# Option B: Export environment variables
export ANTHROPIC_API_KEY="your-api-key"              # or CLAUDE_CODE_OAUTH_TOKEN
export CLAUDE_CODE_MAX_OUTPUT_TOKENS=64000           # recommended

# 3. Install dependencies and build
pnpm install
pnpm build

# 4. Run a pentest
./shanom start -u https://your-app.com -r /path/to/your-repo
```

Shanom will build the worker image locally, start the infrastructure, and launch an ephemeral worker container for the scan.

### Prepare Your Repository

Shanom can scan any repository on your machine. Pass an absolute or relative path with `-r`.

Examples:

```bash
npx @keygraph/shanom start -u https://example.com -r /path/to/repo
```

<details>
<summary>Clone and Build command equivalents</summary>

```bash
./shanom start -u https://example.com -r ./relative/path
```

</details>

### Common Commands

#### Monitoring Progress

```bash
npx @keygraph/shanom logs <workspace>
npx @keygraph/shanom status
```

Open the Temporal Web UI for detailed monitoring:

```bash
open http://localhost:8233
```

<details>
<summary>Clone and Build command equivalents</summary>

```bash
./shanom logs <workspace>
./shanom status
```

</details>

#### Stopping Shanom

```bash
npx @keygraph/shanom stop
npx @keygraph/shanom stop --clean
npx @keygraph/shanom uninstall
```

<details>
<summary>Clone and Build command equivalents</summary>

```bash
./shanom stop
./shanom stop --clean
```

</details>

#### Usage Examples

```bash
# Basic pentest
npx @keygraph/shanom start -u https://example.com -r /path/to/repo

# With a configuration file
npx @keygraph/shanom start -u https://example.com -r /path/to/repo -c /path/to/my-config.yaml

# Custom output directory
npx @keygraph/shanom start -u https://example.com -r /path/to/repo -o ./my-reports

# Named workspace
npx @keygraph/shanom start -u https://example.com -r /path/to/repo -w q1-audit

# List all workspaces
npx @keygraph/shanom workspaces
```

<details>
<summary>Clone and Build command equivalents</summary>

```bash
# Basic pentest
./shanom start -u https://example.com -r /path/to/repo

# With a configuration file
./shanom start -u https://example.com -r /path/to/repo -c /path/to/my-config.yaml

# Custom output directory
./shanom start -u https://example.com -r /path/to/repo -o ./my-reports

# Named workspace
./shanom start -u https://example.com -r /path/to/repo -w q1-audit

# List all workspaces
./shanom workspaces

# Rebuild worker image
./shanom build --no-cache
```

</details>

### Workspaces and Resuming

Shanom supports **workspaces** that allow you to resume interrupted or failed runs without re-running completed agents.

**How it works:**

- Every run creates a workspace (auto-named by default, for example `example-com_shanom-1771007534808`)
- Workspaces are stored in `./workspaces/` (local mode) or `~/.shanom/workspaces/` (npx mode)
- Use `-w <name>` to give your run a custom name for easier reference
- To resume any run, pass its workspace name via `-w` — Shanom detects which agents completed successfully and picks up where it left off
- Each agent's progress is checkpointed via git commits, so resumed runs start from a clean, validated state

```bash
# Start with a named workspace
npx @keygraph/shanom start -u https://example.com -r /path/to/repo -w my-audit

# Resume the same workspace (skips completed agents)
npx @keygraph/shanom start -u https://example.com -r /path/to/repo -w my-audit

# Resume an auto-named workspace from a previous run
npx @keygraph/shanom start -u https://example.com -r /path/to/repo -w example-com_shanom-1771007534808

# List all workspaces and their status
npx @keygraph/shanom workspaces
```

<details>
<summary>Clone and Build command equivalents</summary>

```bash
./shanom start -u https://example.com -r /path/to/repo -w my-audit
./shanom start -u https://example.com -r /path/to/repo -w my-audit
./shanom start -u https://example.com -r /path/to/repo -w example-com_shanom-1771007534808
./shanom workspaces
```

</details>

> [!NOTE]
> The `URL` must match the original workspace URL when resuming. Shanom will reject mismatched URLs to prevent cross-target contamination.

### Credentials and Configuration

#### Credential Precedence

**Local mode** resolves credentials from:

1. **Environment variables** - `export ANTHROPIC_API_KEY=...`
2. **`.env` file** - `./.env`

**npx mode** uses TOML instead of `.env`:

1. **Environment variables** - `export ANTHROPIC_API_KEY=...`
2. **`~/.shanom/config.toml`** - created by `npx @keygraph/shanom setup`

Environment variables always win, so you can override saved config for a single session without editing files.

#### Configuration (Optional)

While you can run without a config file, creating one enables authenticated testing and customized analysis. Pass any configuration file path with `-c`.

##### Create Configuration File

Copy and modify the example configuration:

```bash
cp configs/example-config.yaml ./my-app-config.yaml
```

##### Basic Configuration Structure

```yaml
# Optional: describe your target environment (max 500 chars)
description: "Next.js e-commerce app on PostgreSQL. Local dev environment — .env files contain local-only credentials, not deployed to production."

authentication:
  login_type: form
  login_url: "https://your-app.com/login"
  credentials:
    username: "test@example.com"
    password: "yourpassword"
    totp_secret: "LB2E2RX7XFHSTGCK"  # Optional for 2FA

  login_flow:
    - "Type $username into the email field"
    - "Type $password into the password field"
    - "Click the 'Sign In' button"

  success_condition:
    type: url_contains
    value: "/dashboard"

rules:
  avoid:
    - description: "AI should avoid testing logout functionality"
      type: path
      url_path: "/logout"

  focus:
    - description: "AI should emphasize testing API endpoints"
      type: path
      url_path: "/api"
```

Run with:

```bash
npx @keygraph/shanom start -u https://example.com -r /path/to/repo -c ./my-app-config.yaml
```

<details>
<summary>Clone and Build command equivalents</summary>

```bash
./shanom start -u https://example.com -r /path/to/repo -c ./my-app-config.yaml
```

</details>

#### TOTP Setup for 2FA

If your application uses two-factor authentication, simply add the TOTP secret to your config file. The AI will automatically generate the required codes during testing.

#### Subscription Plan Rate Limits

Anthropic subscription plans reset usage on a **rolling 5-hour window**. The default retry strategy (30-min max backoff) will exhaust retries before the window resets. Add this to your config:

```yaml
pipeline:
  retry_preset: subscription          # Extends max backoff to 6h, 100 retries
  max_concurrent_pipelines: 2         # Run 2 of 5 pipelines at a time (reduces burst API usage)
```

`max_concurrent_pipelines` controls how many vulnerability pipelines run simultaneously (1-5, default: 5). Lower values reduce the chance of hitting rate limits but increase wall-clock time.

### AWS Bedrock

Shanom also supports [Amazon Bedrock](https://aws.amazon.com/bedrock/) instead of using an Anthropic API key.

#### Quick Setup

Run `npx @keygraph/shanom setup` and select **AWS Bedrock**. The wizard will prompt for your region, bearer token, and model IDs.

Or export env vars directly:

```bash
export CLAUDE_CODE_USE_BEDROCK=1
export AWS_REGION=us-east-1
export AWS_BEARER_TOKEN_BEDROCK=your-bearer-token
export ANTHROPIC_SMALL_MODEL=us.anthropic.claude-haiku-4-5-20251001-v1:0
export ANTHROPIC_MEDIUM_MODEL=us.anthropic.claude-sonnet-4-6
export ANTHROPIC_LARGE_MODEL=us.anthropic.claude-opus-4-6
```

<details>
<summary>Clone and Build: add to .env instead</summary>

```bash
CLAUDE_CODE_USE_BEDROCK=1
AWS_REGION=us-east-1
AWS_BEARER_TOKEN_BEDROCK=your-bearer-token
ANTHROPIC_SMALL_MODEL=us.anthropic.claude-haiku-4-5-20251001-v1:0
ANTHROPIC_MEDIUM_MODEL=us.anthropic.claude-sonnet-4-6
ANTHROPIC_LARGE_MODEL=us.anthropic.claude-opus-4-6
```

</details>

Shanom uses three model tiers: **small** (`claude-haiku-4-5-20251001`) for summarization, **medium** (`claude-sonnet-4-6`) for security analysis, and **large** (`claude-opus-4-6`) for deep reasoning. Set `ANTHROPIC_SMALL_MODEL`, `ANTHROPIC_MEDIUM_MODEL`, and `ANTHROPIC_LARGE_MODEL` to the Bedrock model IDs for your region.

### Google Vertex AI

Shanom also supports [Google Vertex AI](https://cloud.google.com/vertex-ai) instead of using an Anthropic API key.

Create a service account with the `roles/aiplatform.user` role in the [GCP Console](https://console.cloud.google.com/iam-admin/serviceaccounts), then download a JSON key file.

#### Quick Setup

Run `npx @keygraph/shanom setup` and select **Google Vertex AI**. The wizard will prompt for your region, project ID, service account key file path, and model IDs. The key file is securely copied to `~/.shanom/google-sa-key.json`.

Or export env vars directly:

```bash
export CLAUDE_CODE_USE_VERTEX=1
export CLOUD_ML_REGION=us-east5
export ANTHROPIC_VERTEX_PROJECT_ID=your-gcp-project-id
export GOOGLE_APPLICATION_CREDENTIALS=/path/to/your-sa-key.json
export ANTHROPIC_SMALL_MODEL=claude-haiku-4-5@20251001
export ANTHROPIC_MEDIUM_MODEL=claude-sonnet-4-6
export ANTHROPIC_LARGE_MODEL=claude-opus-4-6
```

<details>
<summary>Clone and Build: add to .env instead</summary>

```bash
CLAUDE_CODE_USE_VERTEX=1
CLOUD_ML_REGION=us-east5
ANTHROPIC_VERTEX_PROJECT_ID=your-gcp-project-id
GOOGLE_APPLICATION_CREDENTIALS=./credentials/google-sa-key.json
ANTHROPIC_SMALL_MODEL=claude-haiku-4-5@20251001
ANTHROPIC_MEDIUM_MODEL=claude-sonnet-4-6
ANTHROPIC_LARGE_MODEL=claude-opus-4-6
```

</details>

Set `CLOUD_ML_REGION=global` for global endpoints, or a specific region like `us-east5`. Some models may not be available on global endpoints — see the [Vertex AI Model Garden](https://console.cloud.google.com/vertex-ai/model-garden) for region availability.

### Custom Base URL

Shanom supports pointing the SDK at any Anthropic-compatible endpoint (proxies, gateways, etc.) via `ANTHROPIC_BASE_URL`.

Run `npx @keygraph/shanom setup` and select **Custom Base URL**. The wizard will prompt for your endpoint URL, auth token, and optionally let you override the default model tiers.

Or export env vars directly:

```bash
export ANTHROPIC_BASE_URL=https://your-proxy.example.com
export ANTHROPIC_AUTH_TOKEN=your-auth-token

# Optionally override model tiers (defaults are used if not set)
export ANTHROPIC_SMALL_MODEL=claude-haiku-4-5-20251001
export ANTHROPIC_MEDIUM_MODEL=claude-sonnet-4-6
export ANTHROPIC_LARGE_MODEL=claude-opus-4-6
```

<details>
<summary>Clone and Build: add to .env instead</summary>

```bash
ANTHROPIC_BASE_URL=https://your-proxy.example.com
ANTHROPIC_AUTH_TOKEN=your-auth-token
ANTHROPIC_SMALL_MODEL=claude-haiku-4-5-20251001
ANTHROPIC_MEDIUM_MODEL=claude-sonnet-4-6
ANTHROPIC_LARGE_MODEL=claude-opus-4-6
```

</details>

### [EXPERIMENTAL - UNSUPPORTED] Router Mode (Alternative Providers)

Shanom can experimentally route requests through alternative AI providers using claude-code-router. This mode is not officially supported and is intended primarily for:

- **Model experimentation** — try Shanom with GPT-5.2 or Gemini 3-family models

#### Quick Setup

Run `npx @keygraph/shanom setup` and select **Router**. The wizard will prompt you to choose a provider (OpenAI or OpenRouter), enter your API key, and select a default model.

Or export env vars directly:

```bash
export OPENAI_API_KEY=sk-...          # or OPENROUTER_API_KEY=sk-or-...
export ROUTER_DEFAULT=openai,gpt-5.2  # provider,model format
```

```bash
npx @keygraph/shanom start -u https://example.com -r /path/to/repo --router
```

<details>
<summary>Clone and Build: add to .env and run with --router</summary>

```bash
OPENAI_API_KEY=sk-...
# OR
OPENROUTER_API_KEY=sk-or-...
ROUTER_DEFAULT=openai,gpt-5.2
```

```bash
./shanom start -u https://example.com -r /path/to/repo --router
```

</details>

#### Experimental Models

| Provider | Models |
|----------|--------|
| OpenAI | gpt-5.2, gpt-5-mini |
| OpenRouter | google/gemini-3-flash-preview |

#### Disclaimer

This feature is experimental and unsupported. Output quality depends heavily on the model. Shanom is built on top of the Anthropic Agent SDK and is optimized and primarily tested with Anthropic Claude models. Alternative providers may produce inconsistent results (including failing early phases like Recon) depending on the model and routing setup.

### Platform-Specific Instructions

**For Windows:**

*Native (Git Bash):*

Install [Git for Windows](https://git-scm.com/install/windows) and run Shanom from **Git Bash** with Docker Desktop installed. Both `npx @keygraph/shanom` and local clone mode are supported.

*WSL2 (Recommended):*

**Step 1: Ensure WSL 2**

```powershell
wsl --install
wsl --set-default-version 2

# Check installed distros
wsl --list --verbose

# If you don't have a distro, install one (Ubuntu 24.04 recommended)
wsl --list --online
wsl --install Ubuntu-24.04

# If your distro shows VERSION 1, convert it to WSL 2:
wsl --set-version <distro-name> 2
```

See [WSL basic commands](https://learn.microsoft.com/en-us/windows/wsl/basic-commands) for reference.

**Step 2: Install Docker Desktop on Windows** and enable **WSL2 backend** under *Settings > General > Use the WSL 2 based engine*.

**Step 3: Run Shanom inside WSL** using either flow.

**npx inside WSL:**

```bash
npx @keygraph/shanom setup
npx @keygraph/shanom start -u https://your-app.com -r /path/to/your-repo
```

<details>
<summary>Clone and Build command equivalents</summary>

```bash
git clone https://github.com/JonusNattapong/shanom.git
cd shanom
cp .env.example .env  # Edit with your API key
./shanom start -u https://your-app.com -r /path/to/your-repo
```

</details>

To access the Temporal Web UI, run `ip addr` inside WSL to find your WSL IP address, then navigate to `http://<wsl-ip>:8233` in your Windows browser.

Windows Defender may flag exploit code in reports as false positives; see [Antivirus False Positives](#6-windows-antivirus-false-positives) below.

**For Linux (Native Docker):**

You may need to run commands with `sudo` depending on your Docker setup. If you encounter permission issues with output files, ensure your user has access to the Docker socket.

**For macOS:**

Works out of the box with Docker Desktop installed.

**Testing Local Applications:**

Docker containers cannot reach `localhost` on your host machine. Use `host.docker.internal` in place of `localhost`:

```bash
npx @keygraph/shanom start -u http://host.docker.internal:3000 -r /path/to/repo
```

<details>
<summary>Clone and Build command equivalents</summary>

```bash
./shanom start -u http://host.docker.internal:3000 -r /path/to/repo
```

</details>

### Output and Results

All results are saved to the workspaces directory: `./workspaces/` (local mode) or `~/.shanom/workspaces/` (npx mode). Use `-o <path>` to copy deliverables to a custom output directory after the run completes.

Output structure:

```text
workspaces/{hostname}_{sessionId}/
├── session.json          # Metrics and session data
├── workflow.log          # Human-readable workflow log
├── agents/               # Per-agent execution logs
├── prompts/              # Prompt snapshots for reproducibility
└── deliverables/
    ├── comprehensive_security_assessment_report.md   # Main report
    ├── cpg/
    │   ├── cpg_security_analysis.md                # CPG findings
    │   └── cpg_findings.json                       # Structured data
    ├── correlation/
    │   ├── correlation_report.md                   # Unified findings
    │   └── unified_findings.sarif                  # SARIF format
    ├── technical_pentest_report.md                  # Technical details
    ├── remediation_guidance_report.md              # Fix instructions
    └── board_executive_security_report.md            # Executive summary
```

---

## Sample Reports

Sample penetration test reports from industry-standard vulnerable applications:

#### **OWASP Juice Shop** • [GitHub](https://github.com/juice-shop/juice-shop)

*A notoriously insecure web application maintained by OWASP, designed to test a tool's ability to uncover a wide range of modern vulnerabilities.*

**Results**: Identified over 20 vulnerabilities across targeted OWASP categories in a single automated run.

**Notable findings**:

- Authentication bypass and full user database exfiltration via SQL injection
- Privilege escalation to administrator through registration workflow bypass
- IDOR vulnerabilities enabling access to other users' data and shopping carts
- SSRF enabling internal network reconnaissance

[View Complete Report →](sample-reports/shanom-report-juice-shop.md)

---

#### **c{api}tal API** • [GitHub](https://github.com/Checkmarx/capital)

*An intentionally vulnerable API from Checkmarx, designed to test a tool's ability to uncover the OWASP API Security Top 10.*

**Results**: Identified approximately 15 critical and high-severity vulnerabilities.

**Notable findings**:

- Root-level command injection via denylist bypass in a hidden debug endpoint
- Authentication bypass through a legacy, unpatched v1 API endpoint
- Privilege escalation via Mass Assignment in the user profile update function
- Zero false positives for XSS (correctly confirmed robust XSS defenses)

[View Complete Report →](sample-reports/shanom-report-capital-api.md)

---

#### **OWASP crAPI** • [GitHub](https://github.com/OWASP/crAPI)

*A modern, intentionally vulnerable API from OWASP, designed to benchmark a tool's effectiveness against the OWASP API Security Top 10.*

**Results**: Identified over 15 critical and high-severity vulnerabilities.

**Notable findings**:

- Authentication bypass via multiple JWT attacks (Algorithm Confusion, alg:none, weak key injection)
- Full PostgreSQL database compromise via injection, exfiltrating user credentials
- SSRF attack forwarding internal authentication tokens to an external service
- Zero false positives for XSS (correctly identified robust XSS defenses)

[View Complete Report →](sample-reports/shanom-report-crapi.md)

---

## Benchmark

Shanom Lite scored **96.15% (100/104 exploits)** on a hint-free, source-aware variant of the XBOW security benchmark.

**[Full results with detailed agent logs and per-challenge pentest reports →](https://github.com/JonusNattapong/xbow-validation-benchmarks/blob/main/xben-benchmark-results/)**

---

## Architecture

Shanom uses a multi-agent architecture that combines white-box source code analysis with dynamic exploitation across five phases:

```
        ┌──────────────────────────────────────────────────┐
        │         STATIC ANALYSIS (CPG Engine)             │
        ├──────────────────────────────────────────────────┤
        │  ┌──────────────┐  ┌──────────────┐  ┌─────────┐ │
        │  │ Data Flow    │  │ Point Issues │  │ Secrets │ │
        │  │ Analysis     │  │ Detection    │  │ Detection│ │
        │  └──────┬───────┘  └──────┬───────┘  └────┬────┘ │
        │         │                │                │      │
        │         └────────────────┴────────────────┘      │
        │                          │                       │
        │                    ┌─────▼─────┐                │
        │                    │ CPG Graph │                │
        │                    └─────┬─────┘                │
        └──────────────────────────┼──────────────────────┘
                                   │
        ┌──────────────────────────┼──────────────────────┐
        │   Pre-Reconnaissance   │                      │
        │  (nmap, subfinder,     │                      │
        │   whatweb, CPG scan)   │                      │
        └──────────┬─────────────┘                      │
                   │                                    │
                   ▼                                    │
        ┌──────────────────────┐                       │
        │   Reconnaissance     │                       │
        │  (attack surface     │                       │
        │   mapping)           │                       │
        └──────────┬───────────┘                       │
                   │                                    │
                   ▼                                    ▼
        ┌──────────┴───────────┐         ┌──────────────────────┐
        │          │           │         │ Static-Dynamic     │
        ▼          ▼           ▼         │ Correlation        │
  ┌───────────┐ ┌───────────┐ ┌───────────┐  (validate with  │
  │ Vuln      │ │ Vuln      │ │   ...     │   PoC exploits)   │
  │(Injection)│ │  (XSS)    │ │           │                   │
  └─────┬─────┘ └─────┬─────┘ └─────┬─────┘                   │
        │              │             │                       │
        ▼              ▼             ▼                       │
  ┌───────────┐ ┌───────────┐ ┌───────────┐                   │
  │ Exploit   │ │ Exploit   │ │   ...     │                   │
  │(Injection)│ │  (XSS)    │ │           │                   │
  └─────┬─────┘ └─────┬─────┘ └─────┬─────┘                   │
        │              │             │                       │
        └──────┬───────┴─────────────┘                     │
               │                                            │
               ▼                                            │
        ┌──────────────────────┐                           │
        │      Reporting       │◄──────────────────────────┘
        │  (Technical +       │
        │   Remediation +     │
        │   Executive)         │
        └──────────────────────┘
```

### Architectural Overview

Shanom uses Anthropic's Claude Agent SDK as its reasoning engine within a multi-agent architecture. The system combines white-box source code analysis with black-box dynamic exploitation, managed by an orchestrator across five phases. The architecture is designed for minimal false positives through a "no exploit, no report" policy.

Each scan runs in its own ephemeral Docker container (`docker run --rm`) with a per-invocation Temporal task queue, enabling concurrent scans with different target repositories.

---

#### **Phase 1: Pre-Reconnaissance**

External scanning using nmap, subfinder, and whatweb to fingerprint the target's infrastructure and tech stack. Simultaneously performs source code analysis to identify the application framework, entry points, and potential attack surface from the codebase.

#### **Phase 2: Reconnaissance**

Builds a comprehensive attack surface map from the pre-recon findings. Shanom performs live application exploration via browser automation to correlate code-level insights with real-world behavior, producing a detailed map of all entry points, API endpoints, and authentication mechanisms.

#### **Phase 3: Vulnerability Analysis**

To maximize efficiency, this phase operates in parallel with 5 concurrent agents. Using the reconnaissance data, specialized agents for each OWASP category (injection, XSS, auth, authz, SSRF) hunt for potential flaws in parallel. For vulnerabilities like Injection and SSRF, agents perform a structured data flow analysis, tracing user input to dangerous sinks. This phase produces a key deliverable: a list of **hypothesized exploitable paths** that are passed on for validation.

#### **Phase 4: Exploitation**

Continuing the parallel workflow to maintain speed, this phase is dedicated entirely to turning hypotheses into proof. Dedicated exploit agents receive the hypothesized paths and attempt to execute real-world attacks using browser automation, command-line tools, and custom scripts. This phase enforces a strict **"No Exploit, No Report"** policy: if a hypothesis cannot be successfully exploited to demonstrate impact, it is discarded as a false positive.

#### **Phase 5: Reporting**

The final phase compiles all validated findings into a professional, actionable report. An agent consolidates the reconnaissance data and the successful exploit evidence, cleaning up any noise or hallucinated artifacts. Only verified vulnerabilities are included, complete with **reproducible, copy-and-paste Proof-of-Concepts**, delivering a final pentest-grade report focused exclusively on proven risks.


## Coverage and Roadmap

For detailed information about Shanom's security testing coverage and development roadmap, see our [Coverage and Roadmap](./COVERAGE.md) documentation.

## Disclaimers

### Important Usage Guidelines & Disclaimers

Please review the following guidelines carefully before using Shanom (Lite). As a user, you are responsible for your actions and assume all liability.

#### **1. Potential for Mutative Effects & Environment Selection**

This is not a passive scanner. The exploitation agents are designed to **actively execute attacks** to confirm vulnerabilities. This process can have mutative effects on the target application and its data.

> [!WARNING]
> **DO NOT run Shanom on production environments.**
>
> - It is intended exclusively for use on sandboxed, staging, or local development environments where data integrity is not a concern.
> - Potential mutative effects include, but are not limited to: creating new users, modifying or deleting data, compromising test accounts, and triggering unintended side effects from injection attacks.

#### **2. Legal & Ethical Use**

Shanom is designed for legitimate security auditing purposes only.

> [!CAUTION]
> **You must have explicit, written authorization** from the owner of the target system before running Shanom.
>
> Unauthorized scanning and exploitation of systems you do not own is illegal and can be prosecuted under laws such as the Computer Fraud and Abuse Act (CFAA). Keygraph is not responsible for any misuse of Shanom.

#### **3. LLM & Automation Caveats**

- **Verification is Required**: While significant engineering has gone into our "proof-by-exploitation" methodology to eliminate false positives, the underlying LLMs can still generate hallucinated or weakly-supported content in the final report. **Human oversight is essential** to validate the legitimacy and severity of all reported findings.
- **Comprehensiveness**: The analysis in Shanom Lite may not be exhaustive due to the inherent limitations of LLM context windows. For a more comprehensive, graph-based analysis of your entire codebase, **Shanom Pro** leverages its advanced data flow analysis engine to ensure deeper and more thorough coverage.

#### **4. Scope of Analysis**

- **Targeted Vulnerabilities**: The current version of Shanom Lite specifically targets the following classes of *exploitable* vulnerabilities:
  - Broken Authentication & Authorization
  - Injection
  - Cross-Site Scripting (XSS)
  - Server-Side Request Forgery (SSRF)
- **What Shanom Lite Does Not Cover**: This list is not exhaustive of all potential security risks. Shanom Lite's "proof-by-exploitation" model means it will not report on issues it cannot actively exploit, such as vulnerable third-party libraries or insecure configurations. These types of deep static-analysis findings are a core focus of the advanced analysis engine in **Shanom Pro**.

#### **5. Cost & Performance**

- **Time**: As of the current version, a full test run typically takes **1 to 1.5 hours** to complete.
- **Cost**: Running the full test using Anthropic's Claude 4.5 Sonnet model may incur costs of approximately **$50 USD**. Costs vary based on model pricing and application complexity.

#### **6. Windows Antivirus False Positives**

Windows Defender may flag files in `xben-benchmark-results/` or `deliverables/` as malware. These are false positives caused by exploit code in the reports. Add an exclusion for the Shanom directory in Windows Defender, or use Docker/WSL2.

#### **7. Security Considerations**

Shanom Lite is designed for scanning repositories and applications you own or have explicit permission to test. Do not point it at untrusted or adversarial codebases. Like any AI-powered tool that reads source code, Shanom Lite is susceptible to prompt injection from content in the scanned repository.


## License

Shanom Lite is released under the [GNU Affero General Public License v3.0 (AGPL-3.0)](LICENSE).

Shanom is open source (AGPL v3). This license allows you to:
- Use it freely for all internal security testing.
- Modify the code privately for internal use without sharing your changes.

The AGPL's sharing requirements primarily apply to organizations offering Shanom as a public or managed service (such as a SaaS platform). In those specific cases, any modifications made to the core software must be open-sourced.


## Community & Support

### Community Resources

**1:1 Office Hours** — Thursdays, two time zones
Book a free 15-min session for hands-on help with bugs, deployments, or config questions.
→ US/EU: 10:00 AM PT  |  Asia: 2:00 PM IST
→ [Book a slot](https://cal.com/george-flores-keygraph/shanom-community-office-hours)

[Join our Discord](https://discord.gg/cmctpMBXwE) to ask questions, share feedback, and connect with other Shanom users.

**Contributing:** At this time, we're not accepting external code contributions (PRs).  
Issues are welcome for bug reports and feature requests.

- **Report bugs** via [GitHub Issues](https://github.com/JonusNattapong/shanom/issues)
- **Suggest features** in [Discussions](https://github.com/JonusNattapong/shanom/discussions)

### Stay Connected

- **Twitter**: [@JonusNattapong](https://twitter.com/JonusNattapong)
- **LinkedIn**: [Keygraph](https://linkedin.com/company/keygraph)
- **Website**: [keygraph.io](https://keygraph.io)



## Get in Touch

### Shanom Pro

Shanom Pro is Keygraph's all-in-one AppSec platform. For organizations that need unified SAST, SCA, and autonomous pentesting with static-dynamic correlation, CI/CD integration, or self-hosted deployment, see the [Shanom Pro technical overview](./SHANNON-PRO.md).

<p align="center">
  <a href="https://docs.google.com/forms/d/e/1FAIpQLSf-cPZcWjlfBJ3TCT8AaWpf8ztsw3FaHzJE4urr55KdlQs6cQ/viewform?usp=header" target="_blank">
    <img src="https://img.shields.io/badge/Shanom%20Pro%20Inquiry-4285F4?style=for-the-badge&logo=google&logoColor=white" alt="Shanom Pro Inquiry">
  </a>
</p>

**Email**: [shanom@keygraph.io](mailto:shanom@keygraph.io)

---

<p align="center">
  <b>Built by <a href="https://keygraph.io">Keygraph</a></b>
</p>
