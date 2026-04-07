# CLAUDE.md

AI-powered penetration testing agent for defensive security analysis. Automates vulnerability assessment by combining reconnaissance tools with AI-powered code analysis.

## Commands

**Prerequisites:** Docker, AI provider credentials (`.env` for local, `shn setup` or env vars for npx)

### Dual CLI

Shanom supports two CLI modes, auto-detected based on the current working directory:

| | **npx** (`npx shanom`) | **Local** (`./shanom`) |
|---|---|---|
| **Install** | Zero-install via npm | Clone the repo |
| **Image** | Pulled from Docker Hub (`shanom:latest`) | Built locally (`shanom-worker`) |
| **State** | `~/.shanom/` | Project directory |
| **Credentials** | `~/.shanom/config.toml` (via `shn setup`) or env vars | `./.env` |
| **Config** | `~/.shanom/config.toml` (via `shn setup`) | N/A |
| **Prompts** | Bundled in Docker image | Mounted from `./apps/worker/prompts/` (live-editable) |

Mode auto-detection: local mode activates when env var `SHANOM_LOCAL=1` is set by the `./shanom` entry point (`apps/cli/src/mode.ts`). Otherwise npx mode.

### AI Providers

Supported authentication methods:

| Provider | Setup | Models |
|----------|-------|--------|
| **Anthropic (Claude)** | `ANTHROPIC_API_KEY` or `CLAUDE_CODE_OAUTH_TOKEN` | claude-opus-4-6, claude-sonnet-4-6, claude-haiku-4-5 |
| **Custom Base URL** | `ANTHROPIC_BASE_URL` + `ANTHROPIC_AUTH_TOKEN` | Compatible endpoints |
| **AWS Bedrock** | `CLAUDE_CODE_USE_BEDROCK=1` + `AWS_BEARER_TOKEN_BEDROCK` | Bedrock Claude models |
| **Google Vertex AI** | `CLAUDE_CODE_USE_VERTEX=1` + `GOOGLE_APPLICATION_CREDENTIALS` | Vertex Claude models |
| **Router Mode** — Multi-provider gateway |
| ├─ **OpenAI** | `OPENAI_API_KEY` + `ROUTER_DEFAULT=openai,gpt-5.2` | gpt-5.2, gpt-5-mini |
| ├─ **OpenRouter** | `OPENROUTER_API_KEY` + `ROUTER_DEFAULT=openrouter,google/gemini-3-flash-preview` | google/gemini-3-flash-preview |
| └─ **Kilocode** | `KILOCODE_API_KEY` + `ROUTER_DEFAULT=kilocode,anthropic/claude-sonnet-4.6` | anthropic/claude-sonnet-4.6, openai/gpt-5.2, kilo-auto/frontier |

### Using Kilocode

[Kilocode](https://kilo.ai) provides access to frontier coding models through a unified API gateway.

**Setup via `npx shanom setup`:**
```bash
npx shanom setup
# → Select "Router"
# → Select "Kilocode"  
# → Enter your Kilocode API key
# → Choose default model (Claude Sonnet 4.6, Claude Opus 4.6, GPT-5.2, or Kilocode Auto)
```

**Setup via environment variables:**
```bash
export KILOCODE_API_KEY=your-kilocode-api-key
export ROUTER_DEFAULT=kilocode,anthropic/claude-sonnet-4.6
./shanom start -u <url> -r <repo>
```

**Available Kilocode models:**
- `anthropic/claude-sonnet-4.6` — Recommended for most tasks
- `anthropic/claude-opus-4.6` — Best for complex analysis
- `openai/gpt-5.2` — OpenAI's latest model
- `kilo-auto/frontier` — Auto-selects best available model

### npx Quick Start

```bash
# Configure credentials (interactive wizard)
npx shanom setup

# Or export env vars directly (non-interactive / CI)
export ANTHROPIC_API_KEY=your-key

# Run
npx shanom start -u <url> -r /path/to/repo
```

### Local (Development) Quick Start

```bash
# Setup
echo "ANTHROPIC_API_KEY=your-key" > .env

# Build (auto-runs if image missing)
./shanom build

# Run
./shanom start -u <url> -r my-repo
./shanom start -u <url> -r my-repo -c ./apps/worker/configs/my-config.yaml
./shanom start -u <url> -r /any/path/to/repo
```

### Common Commands

```bash
# Setup (npx mode only — one-time credential configuration)
npx shanom setup

# Workspaces & Resume
./shanom start -u <url> -r my-repo -w my-audit    # New named workspace
./shanom start -u <url> -r my-repo -w my-audit    # Resume (same command)
./shanom workspaces                                 # List all workspaces

# Monitor
./shanom logs <workspace>            # Tail workflow log
./shanom status                      # Show running workers
# Temporal Web UI: http://localhost:8233

# Stop
./shanom stop                        # Preserves workflow data
./shanom stop --clean                # Full cleanup including volumes (confirms first)

# Image management
./shanom build [--no-cache]          # Local mode: build worker image
npx shanom uninstall             # npx mode: remove ~/.shanom/ (confirms first)

# Build TypeScript (development)
pnpm run build                       # Build all packages via Turborepo
pnpm run check                       # Type-check all packages
pnpm biome                           # Biome lint + format + import sorting check
pnpm biome:fix                       # Auto-fix lint, format, and import sorting
```

**Monorepo tooling:** pnpm workspaces, Turborepo for task orchestration, Biome for linting/formatting. TypeScript compiler options shared via `tsconfig.base.json` at the root. All packages extend it, overriding only `rootDir` and `outDir`. Shared devDependencies (`typescript`, `@types/node`, `turbo`, `@biomejs/biome`) are hoisted to the root workspace.

**Options:** `-c <file>` (YAML config), `-o <path>` (output directory), `-w <name>` (named workspace; auto-resumes if exists), `--pipeline-testing` (minimal prompts, 10s retries), `--router` (multi-model routing via [claude-code-router](https://github.com/musistudio/claude-code-router))

## Architecture

### Monorepo Layout

```
apps/cli/        — shanom (published to npm, bundled with tsdown)
apps/worker/     — @shanom/worker (private, Temporal worker + pipeline logic)
```

### CLI Package (`apps/cli/`)
Published as `shanom` on npm. Contains only Docker orchestration logic — no Temporal SDK, business logic, or prompts. Bundled with tsdown for single-file ESM output.

- `apps/cli/src/index.ts` — CLI dispatcher (`setup`, `start`, `stop`, `logs`, `workspaces`, `status`, `build`, `uninstall`, `info`)
- `apps/cli/src/mode.ts` — Auto-detection: local mode if `SHANOM_LOCAL=1` env var is set
- `apps/cli/src/docker.ts` — Compose lifecycle, image pull/build, ephemeral `docker run` worker spawning
- `apps/cli/src/home.ts` — State directory management (`~/.shanom/` for npx, `./` for local)
- `apps/cli/src/env.ts` — `.env` loading, TOML fallback (npx only) via `apps/cli/src/config/resolver.ts`, credential validation, env flag building
- `apps/cli/src/config/resolver.ts` — Cascading config (npx only): env vars → `~/.shanom/config.toml` (parsed with `smol-toml`)
- `apps/cli/src/config/writer.ts` — TOML serialization and secure file persistence (0o600)
- `apps/cli/src/commands/setup.ts` — Interactive TUI wizard (`@clack/prompts`) for provider credential setup (npx only)
- `apps/cli/src/paths.ts` — Repo/config path resolution (bare name → `./repos/<name>`, or any absolute/relative path)
- `apps/cli/src/commands/` — Command handlers
- `apps/cli/infra/compose.yml` — Bundled Temporal + router compose file for npx mode
- `apps/cli/tsdown.config.ts` — tsdown bundler config
- `shanom` — Node.js entry point (`#!/usr/bin/env node`) that delegates to `apps/cli/dist/index.mjs`

### Docker Architecture
Infra (Temporal + router) runs via `docker-compose.yml`. Workers are ephemeral `docker run --rm` containers, one per scan, each with a unique task queue and isolated volume mounts.

- `docker-compose.yml` — Infra only: `shanom-temporal` (port 7233/8233) and `shanom-router` (port 3456, optional via profile). Network: `shanom-net`
- `Dockerfile` — 2-stage build (builder + Chainguard Wolfi runtime). Uses pnpm. Entrypoint: `CMD ["node", "apps/worker/dist/temporal/worker.js"]`
- No `docker-compose.docker.yml` — host gateway handled via `--add-host` flag in CLI

### Worker Package (`apps/worker/`)
- `apps/worker/src/paths.ts` — Centralized path constants (`PROMPTS_DIR`, `CONFIGS_DIR`, `WORKSPACES_DIR`)
- `apps/worker/src/session-manager.ts` — Agent definitions (`AGENTS` record). Agent types in `apps/worker/src/types/agents.ts`
- `apps/worker/src/config-parser.ts` — YAML config parsing with JSON Schema validation
- `apps/worker/src/ai/claude-executor.ts` — Claude Agent SDK integration with retry logic
- `apps/worker/src/services/` — Business logic layer (Temporal-agnostic). Activities delegate here. Key: `agent-execution.ts`, `error-handling.ts`, `container.ts`
- `apps/worker/src/types/` — Consolidated types: `Result<T,E>`, `ErrorCode`, `AgentName`, `ActivityLogger`, etc.
- `apps/worker/src/utils/` — Shared utilities (file I/O, formatting, concurrency)

### Temporal Orchestration
Durable workflow orchestration with crash recovery, queryable progress, intelligent retry, and parallel execution (5 concurrent agents in vuln/exploit phases).

- `apps/worker/src/temporal/workflows.ts` — Main workflow (`pentestPipelineWorkflow`)
- `apps/worker/src/temporal/activities.ts` — Thin wrappers — heartbeat loop, error classification, container lifecycle. Business logic delegated to `apps/worker/src/services/`
- `apps/worker/src/temporal/activity-logger.ts` — `TemporalActivityLogger` implementation of `ActivityLogger` interface
- `apps/worker/src/temporal/summary-mapper.ts` — Maps `PipelineSummary` to `WorkflowSummary`
- `apps/worker/src/temporal/worker.ts` — Combined worker + client entry point (per-invocation task queue, submits workflow, waits for result)
- `apps/worker/src/temporal/shared.ts` — Types, interfaces, query definitions
### Five-Phase Pipeline

1. **Pre-Recon** (`pre-recon`) — External scans (nmap, subfinder, whatweb) + source code analysis
2. **Recon** (`recon`) — Attack surface mapping from initial findings
3. **Vulnerability Analysis** (5 parallel agents) — injection, xss, auth, authz, ssrf
4. **Exploitation** (5 parallel agents, conditional) — Exploits confirmed vulnerabilities
5. **Reporting** (`report`) — Executive-level security report

### Supporting Systems
- **Configuration** — YAML configs in `apps/worker/configs/` with JSON Schema validation (`config-schema.json`). Supports auth settings, MFA/TOTP, and per-app testing parameters. Credential resolution — local mode: env vars → `./.env`; npx mode: env vars → `~/.shanom/config.toml` (via `shn setup`)
- **Prompts** — Per-phase templates in `apps/worker/prompts/` with variable substitution (`{{TARGET_URL}}`, `{{CONFIG_CONTEXT}}`). Shared partials in `apps/worker/prompts/shared/` via `apps/worker/src/services/prompt-manager.ts`
- **SDK Integration** — Uses `@anthropic-ai/claude-agent-sdk` with `maxTurns: 10_000` and `bypassPermissions` mode. Browser automation via `playwright-cli` with session isolation (`-s=<session>`). TOTP generation via `generate-totp` CLI tool. Login flow template at `apps/worker/prompts/shared/login-instructions.txt` supports form, SSO, API, and basic auth
- **Audit System** — Crash-safe append-only logging in `workspaces/{hostname}_{sessionId}/`. Tracks session metrics, per-agent logs, prompts, and deliverables. WorkflowLogger (`apps/worker/src/audit/workflow-logger.ts`) provides unified human-readable per-workflow logs, backed by LogStream (`apps/worker/src/audit/log-stream.ts`) shared stream primitive
- **Deliverables** — Saved to `deliverables/` in the target repo via the `save-deliverable` CLI script (`apps/worker/src/scripts/save-deliverable.ts`)
- **Workspaces & Resume** — Named workspaces via `-w <name>` or auto-named from URL+timestamp. Resume detects completed agents via `session.json`. `loadResumeState()` in `apps/worker/src/temporal/activities.ts` validates deliverable existence, restores git checkpoints, and cleans up incomplete deliverables. Workspace listing via `apps/worker/src/temporal/workspaces.ts`

## Development Notes

### Adding a New Agent
1. Define agent in `apps/worker/src/session-manager.ts` (add to `AGENTS` record). `ALL_AGENTS`/`AgentName` types live in `apps/worker/src/types/agents.ts`
2. Create prompt template in `apps/worker/prompts/` (e.g., `vuln-newtype.txt`)
3. Two-layer pattern: add a thin activity wrapper in `apps/worker/src/temporal/activities.ts` (heartbeat + error classification). `AgentExecutionService` in `apps/worker/src/services/agent-execution.ts` handles the agent lifecycle automatically via the `AGENTS` registry
4. Register activity in `apps/worker/src/temporal/workflows.ts` within the appropriate phase

### Modifying Prompts
- Variable substitution: `{{TARGET_URL}}`, `{{CONFIG_CONTEXT}}`, `{{LOGIN_INSTRUCTIONS}}`
- Shared partials in `apps/worker/prompts/shared/` included via `apps/worker/src/services/prompt-manager.ts`
- Test with `--pipeline-testing` for fast iteration

### Key Design Patterns
- **Configuration-Driven** — YAML configs with JSON Schema validation
- **Progressive Analysis** — Each phase builds on previous results
- **SDK-First** — Claude Agent SDK handles autonomous analysis
- **Modular Error Handling** — `ErrorCode` enum, `Result<T,E>` for explicit error propagation, automatic retry (3 attempts per agent)
- **Services Boundary** — Activities are thin Temporal wrappers; `apps/worker/src/services/` owns business logic, accepts `ActivityLogger`, returns `Result<T,E>`. No Temporal imports in services
- **DI Container** — Per-workflow in `apps/worker/src/services/container.ts`. `AuditSession` excluded (parallel safety)
- **Ephemeral Workers** — Each scan runs in its own `docker run --rm` container with a per-invocation task queue. Temporal routes activities by queue name, so per-scan queues ensure activities never land on a worker with the wrong repo mounted

### Security
Defensive security tool only. Use only on systems you own or have explicit permission to test.

## Code Style Guidelines

### Formatting
Biome handles formatting and linting. Run `pnpm biome:fix` to auto-fix. Config in `biome.json`: single quotes, semicolons, trailing commas, 2-space indent, 120 char line width.

### Clarity Over Brevity
- Optimize for readability, not line count — three clear lines beat one dense expression
- Use descriptive names that convey intent
- Prefer explicit logic over clever one-liners

### Structure
- Keep functions focused on a single responsibility
- Use early returns and guard clauses instead of deep nesting
- Never use nested ternary operators — use if/else or switch
- Extract complex conditions into well-named boolean variables

### TypeScript Conventions
- Use `function` keyword for top-level functions (not arrow functions)
- Explicit return type annotations on exported/top-level functions
- Prefer `readonly` for data that shouldn't be mutated
- `exactOptionalPropertyTypes` is enabled — use spread for optional props, not direct `undefined` assignment

### Avoid
- Combining multiple concerns into a single function to "save lines"
- Dense callback chains when sequential logic is clearer
- Sacrificing readability for DRY — some repetition is fine if clearer
- Abstractions for one-time operations
- Backwards-compatibility shims, deprecated wrappers, or re-exports for removed code — delete the old code, don't preserve it

### Comments
Comments must be **timeless** — no references to this conversation, refactoring history, or the AI.

**Patterns used in this codebase:**
- `/** JSDoc */` — file headers (after license) and exported functions/interfaces
- `// N. Description` — numbered sequential steps inside function bodies. Use when a
  function has 3+ distinct phases where at least one isn't immediately obvious from the
  code. Each step marks the start of a logical phase. Reference: `AgentExecutionService.execute`
  (steps 1-9) and `injectModelIntoReport` (steps 1-5)
- `// === Section ===` — high-level dividers between groups of functions in long files,
  or to label major branching/classification blocks (e.g., `// === SPENDING CAP SAFEGUARD ===`).
  Not for sequential steps inside function bodies — use numbered steps for that
- `// NOTE:` / `// WARNING:` / `// IMPORTANT:` — gotchas and constraints

**Never:** obvious comments, conversation references ("as discussed"), history ("moved from X")

## Key Files

**CLI:** `shanom` (entry point), `apps/cli/src/index.ts` (dispatcher), `apps/cli/src/docker.ts` (orchestration), `apps/cli/src/mode.ts` (auto-detection)

**Entry Points:** `apps/worker/src/temporal/workflows.ts`, `apps/worker/src/temporal/activities.ts`, `apps/worker/src/temporal/worker.ts`

**Core Logic:** `apps/worker/src/session-manager.ts`, `apps/worker/src/ai/claude-executor.ts`, `apps/worker/src/config-parser.ts`, `apps/worker/src/services/`, `apps/worker/src/audit/`

**Config:** `docker-compose.yml`, `apps/cli/infra/compose.yml`, `apps/worker/configs/`, `apps/worker/prompts/`, `tsconfig.base.json` (shared compiler options), `turbo.json`, `biome.json`

**CI/CD:** `.github/workflows/release.yml` (Docker Hub push + npm publish + GitHub release, manual dispatch)

## Package Installation

Package managers are configured with a minimum release age (7 days). Requires pnpm >= 10.16.0. If `pnpm install` fails due to a package being too new, **do not attempt to bypass it** — report the blocked package to the user and stop.

## Troubleshooting

- **"Repository not found"** — Pass a bare name (`-r my-repo`) for `./repos/my-repo`, or a path (`-r /path/to/repo`) for any directory
- **"Temporal not ready"** — Wait for health check or `docker compose logs temporal`
- **Worker not processing** — Check `docker ps --filter "name=shanom-worker-"`
- **Reset state** — `./shanom stop --clean`
- **Local apps unreachable** — Use `host.docker.internal` instead of `localhost`
- **Missing tools** — Use `--pipeline-testing` to skip nmap/subfinder/whatweb (graceful degradation)
- **Container permissions** — On Linux, may need `sudo` for docker commands
