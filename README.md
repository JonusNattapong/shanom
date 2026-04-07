# Shanom — AI-Powered AppSec Platform

<p align="center">
  <img src="./assets/github-banner.png" alt="Shanom" width="100%">
</p>

<p align="center">
  <a href="https://github.com/JonusNattapong/shanom/releases"><img src="https://img.shields.io/github/v/release/JonusNattapong/shanom?style=flat-square" alt="Release"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-AGPL--3.0-blue.svg?style=flat-square" alt="License"></a>
  <a href="https://discord.gg/cmctpMBXwE"><img src="https://img.shields.io/discord/1234567890?color=7289da&label=Discord&logo=discord&logoColor=white&style=flat-square" alt="Discord"></a>
</p>

**Shanom** is an open-source, AI-powered Application Security (AppSec) platform that combines advanced static analysis (SAST, SCA, Secrets Detection) with autonomous dynamic penetration testing. Built with a Code Property Graph (CPG) engine and LLM reasoning at every node, Shanom validates every finding with a working proof-of-concept exploit.

---

## 🚀 What Makes Shanom Different

| Traditional Tools | Shanom |
|------------------|--------|
| Pattern-based SAST with high false positives | **CPG + LLM reasoning** for contextual analysis |
| SCA flags all CVEs without context | **Reachability analysis** — only flag reachable vulnerabilities |
| Static and dynamic tools don't talk | **Static-Dynamic Correlation** — every finding validated with PoC |
| Secrets scanners miss custom formats | **Regex + LLM + Entropy** — multi-layer detection |
| Separate tools for SAST, SCA, pentest | **Unified platform** — one workflow, complete coverage |

---

## ✨ Core Capabilities

### 🧠 CPG Engine with LLM Reasoning

Shanom transforms your codebase into a **Code Property Graph** (CPG) combining:
- **AST** (Abstract Syntax Tree) — code structure
- **CFG** (Control Flow Graph) — execution paths  
- **PDG** (Program Dependence Graph) — data dependencies

At **every node**, an LLM evaluates security properties:
- Data flow from sources (user input) to sinks (dangerous operations)
- Context-aware sanitization assessment
- Business logic invariant discovery

### 🔍 Static Analysis (SAST)

**Point Issue Detection** identifies single-location vulnerabilities:
- Weak cryptography (MD5, SHA1, DES, RC4)
- Hardcoded credentials (API keys, passwords, tokens)
- Insecure configuration (disabled SSL, debug mode)
- Missing security headers (CSP, HSTS, X-Frame-Options)
- Weak random number generation
- Disabled certificate validation
- Overly permissive CORS

**Data Flow Analysis** traces vulnerabilities across the codebase:
- Source-to-sink path analysis
- Taint tracking through function calls
- Sanitization effectiveness assessment

### 📦 SCA with Reachability Analysis

Unlike traditional SCA tools that flag every CVE, Shanom:
- Parses lock files (npm, yarn, pip, poetry, cargo, etc.)
- Queries CVE databases (NVD, OSV)
- **Traces reachability** via CPG — is the vulnerable function actually called?
- Prioritizes reachable vulnerabilities
- Provides upgrade paths with complexity assessment

### 🔐 Secrets Detection

Three-layer detection approach:
1. **Regex patterns** — AWS keys, GitHub tokens, JWT secrets, etc.
2. **LLM detection** — Custom formats, dynamically constructed credentials
3. **Entropy analysis** — High-randomness strings that may be secrets

Features:
- Context-aware validation (excludes test/example data)
- Liveness checks (read-only validation against services)
- Masked output with previews for safe reporting

### 🔗 Static-Dynamic Correlation

The core innovation: **every static finding is validated dynamically**.

```
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────┐
│  Static Finding │────→│  Dynamic Exploit │────→│  Validated PoC  │
│  (CPG Analysis) │     │  (Live Testing)  │     │  (Reported)     │
└─────────────────┘     └──────────────────┘     └─────────────────┘
```

Correlation statuses:
- ✅ **CONFIRMED** — Static finding successfully exploited
- ⚠️ **UNCONFIRMED** — Found statically, exploit failed (potential false positive)
- ❌ **FALSE_POSITIVE** — Static pattern matched but not exploitable
- 🎯 **DYNAMIC_ONLY** — Exploited but not found in static analysis

### 🏢 Enterprise Platform (Optional)

For organizations needing centralized AppSec:
- **Multi-tenancy** — Logical, container, or VPC isolation
- **RBAC** — Role-based access control (Admin, Security Engineer, Developer, Viewer)
- **SSO/SAML/OIDC** — Enterprise authentication
- **CI/CD Integration** — GitHub Actions, GitLab CI, Jenkins, Azure DevOps
- **Quality Gates** — Block builds on vulnerability thresholds
- **Audit Logging** — Compliance tracking (SOC2, ISO27001)

---

## 📋 Quick Start

### Prerequisites

- **Docker** — Container runtime
- **Node.js 18+** — For CLI usage
- **AI Provider** — Anthropic API key, AWS Bedrock, or Google Vertex AI

### Install & Run

```bash
# Option 1: Using npx (recommended)
npx @keygraph/shanom setup
npx @keygraph/shanom start \
  -u https://your-app.com \
  -r /path/to/your-repo

# Option 2: Clone and build
git clone https://github.com/JonusNattapong/shanom.git
cd shanom
pnpm install
pnpm build
./shanom start \
  -u https://your-app.com \
  -r /path/to/your-repo
```

### Test with Vulnerable App

```bash
# Start test application
cd test-app
npm install
npm start  # Runs on http://localhost:3000

# In another terminal, run Shanom
cd ..
./shanom start \
  -u http://localhost:3000 \
  -r ./test-app \
  -w demo-scan
```

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    STATIC ANALYSIS ENGINE                        │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────┐  │
│  │ CPG Builder  │→ │ Data Flow    │→ │ Vulnerability        │  │
│  │ (AST+CFG+PDG)│  │ Analyzer     │  │ Detection            │  │
│  └──────────────┘  └──────────────┘  └──────────────────────┘  │
│         │                                    │                   │
│         ↓                                    ↓                   │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐         │
│  │ SAST Point   │  │ SCA with     │  │ Secrets      │         │
│  │ Issues       │  │ Reachability │  │ Detection    │         │
│  └──────────────┘  └──────────────┘  └──────────────┘         │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│                   EXPLOITATION QUEUE                           │
│         (Static findings injected as test targets)               │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│              DYNAMIC PENETRATION TESTING                       │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐  │
│  │ Injection│ │ XSS     │ │ Auth    │ │ Authz   │ │ SSRF    │  │
│  │ Agent   │ │ Agent   │ │ Agent   │ │ Agent   │ │ Agent   │  │
│  └────┬────┘ └────┬────┘ └────┬────┘ └────┬────┘ └────┬────┘  │
│       │           │           │           │           │        │
│       └───────────┴───────────┴───────────┴───────────┘        │
│                              │                                   │
│                              ↓                                   │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │              STATIC-DYNAMIC CORRELATION                   │  │
│  │     (Validate findings, remove false positives)           │  │
│  └──────────────────────────────────────────────────────────┘  │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│                     REPORTING ENGINE                           │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐   │
│  │ Technical       │  │ Remediation     │  │ Executive       │   │
│  │ Pentest Report  │  │ Guidance Report │  │ Board Report    │   │
│  │                 │  │                 │  │                 │   │
│  │ • CVSS scores   │  │ • Fix steps     │  │ • Risk summary  │   │
│  │ • PoC exploits  │  │ • Effort est.   │  │ • Business impact│   │
│  │ • Code refs     │  │ • Prevention    │  │ • Compliance    │   │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘   │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

## 📊 Output & Reports

Shanom generates multiple report formats:

```
workspaces/{hostname}_{sessionId}/
├── session.json                     # Session metrics
├── workflow.log                     # Execution log
├── deliverables/
│   ├── comprehensive_security_assessment_report.md
│   ├── technical_pentest_report.md          # Detailed findings
│   ├── remediation_guidance_report.md       # Fix instructions
│   ├── board_executive_security_report.md   # Executive summary
│   ├── cpg/
│   │   ├── cpg_security_analysis.md
│   │   └── cpg_findings.json
│   ├── correlation/
│   │   ├── correlation_report.md
│   │   └── unified_findings.sarif   # SARIF for CI/CD
│   └── sca/
│       ├── sca_report.md
│       └── dependency_vulnerabilities.json
```

---

## 🛡️ Security Coverage

### Vulnerability Categories

| Category | Static Detection | Dynamic Validation | Status |
|----------|-----------------|-------------------|--------|
| **Injection** (SQL, NoSQL, Command, LDAP) | ✅ Data flow analysis | ✅ Exploitation with PoC | Production Ready |
| **XSS** (Reflected, Stored, DOM) | ✅ Source-sink tracing | ✅ Browser automation | Production Ready |
| **Authentication** | ✅ Pattern detection | ✅ Credential stuffing, session attacks | Production Ready |
| **Authorization** (IDOR, privilege escalation) | ✅ Business logic analysis | ✅ Role-based testing | Production Ready |
| **SSRF** | ✅ URL analysis | ✅ Outbound request validation | Production Ready |
| **Cryptography** | ✅ Weak algorithm detection | — | Static Only |
| **Secrets** | ✅ Multi-layer detection | — | Static Only |
| **Configuration** | ✅ Security misconfig detection | — | Static Only |

---

## 🔧 Configuration

### Basic Config File

```yaml
# my-app-config.yaml
description: "Next.js e-commerce app on PostgreSQL"

authentication:
  login_type: form
  login_url: "https://app.com/login"
  credentials:
    username: "test@example.com"
    password: "testpass"
    totp_secret: "LB2E2RX7XFHSTGCK"
  login_flow:
    - "Type $username into email field"
    - "Type $password into password field"
    - "Click 'Sign In'"
  success_condition:
    type: url_contains
    value: "/dashboard"

rules:
  avoid:
    - description: "Skip logout endpoints"
      type: path
      url_path: "/logout"
  focus:
    - description: "Test API endpoints"
      type: path
      url_path: "/api/"
```

### Enterprise Config

```yaml
# enterprise-config.yaml
organization:
  name: "Acme Corp"
  plan: "enterprise"
  
auth:
  mode: sso
  providers:
    - type: google
    - type: saml
      
rbac:
  roles:
    - name: "Security Engineer"
      permissions: [scan:trigger, finding:read, report:export]
      
integrations:
  cicd:
    - type: github-actions
      autoBlockOnFailure: true
      qualityGateRules:
        - severity: critical
          maxFindings: 0
```

---

## 🧪 Testing & Validation

Run the built-in validation suite:

```bash
# Validate platform installation
node validate-platform.mjs

# Run live demo on test app
node live-demo.mjs

# Full test suite
pnpm test
```

---

## 📦 Deployment Options

### Local Mode (Default)
- Direct CLI execution
- Local Docker containers
- File-based storage
- Single user/organization

### Enterprise Mode
- Multi-tenant platform
- Database-backed storage
- RBAC and SSO
- CI/CD integration
- API access

### Self-Hosted Runner
- Customer infrastructure
- Code never leaves your network
- Use your own LLM API keys
- Control plane for orchestration

---

## 🤝 Community & Support

- **Discord:** [Join our community](https://discord.gg/cmctpMBXwE)
- **Issues:** [GitHub Issues](https://github.com/JonusNattapong/shanom/issues)
- **Discussions:** [GitHub Discussions](https://github.com/JonusNattapong/shanom/discussions)
- **Twitter:** [@JonusNattapong](https://twitter.com/JonusNattapong)

---

## 📄 License

Shanom is released under the [GNU Affero General Public License v3.0 (AGPL-3.0)](LICENSE).

- ✅ Free for internal security testing
- ✅ Modify privately for internal use
- ⚠️ SaaS/commercial use requires open-sourcing modifications

---

## 🙏 Acknowledgments

Shanom leverages the incredible work of:
- **Anthropic** — Claude Agent SDK and LLM reasoning
- **Joern** — CPG research and inspiration
- **OWASP** — Security standards and vulnerable test apps
- **The AppSec community** — Tools, research, and collaboration

---

<p align="center">
  <strong>Built with ❤️ for the security community</strong><br>
  <a href="https://github.com/JonusNattapong/shanom">github.com/JonusNattapong/shanom</a>
</p>
