# RawrXD 45-Day Parity Finish Plan (v1.2.0-beta)

## Mission
Reach practical competitiveness with VS Code + Copilot by closing the highest-value parity gaps in 45 days, with measurable weekly deliverables.

## Baseline Snapshot
- Feature parity: 55%
- Stability: 80%
- Performance: 90%
- Enterprise readiness: 40%

## 45-Day Outcome Targets
- Feature parity >= 75%
- Stability >= 90%
- Enterprise readiness >= 60%
- Critical-path gaps closed for Tooling, LSP polish, and Workspace parity

## Workstream A: Tool Ecosystem (Days 1-14)
### A1. Top 10 built-in tool closures
- [ ] Harden `execute_command` security policy and allowlist behavior
- [ ] Implement `get_code_outline` against existing symbol/LSP index paths
- [ ] Implement `edit_file` with inline diff-aware patching
- [ ] Upgrade `terminal_integration` toward robust PTY/session handling
- [ ] Expand `git_operations` beyond basic status/diff/commit
- [ ] Implement `browser_integration` via headless WebView2 lane
- [ ] Implement `api_testing` (REST/GraphQL smoke lane)
- [ ] Improve `test_generation` from basic scaffolds to runnable suites
- [ ] Upgrade `refactoring_tools` for safe multi-file transforms
- [ ] Upgrade `dependency_analysis` graph depth + filtering

### A2. GitHub PR tool baseline (basic CRUD)
- [ ] create/list/get PR
- [ ] add/resolve PR comments
- [ ] status checks + changed files
- [ ] labels/assignees basic ops

### A3. Tool throughput/reliability
- [x] Add list-directory filesystem hardening
- [x] Add registry shutdown safety (process-lifetime singleton)
- [ ] Add tool result caching (in progress)
- [ ] Add cache metrics + hit/miss observability

## Workstream B: LSP Polish (Days 15-21)
- [ ] Code lens
- [ ] Inlay hints
- [ ] Call hierarchy
- [ ] Type hierarchy
- [ ] Semantic highlight completion pass

## Workstream C: Copilot Workspace Parity (Days 22-35)
- [ ] Multi-file edit planning contract (plan + apply + rollback)
- [ ] Workspace-wide refactoring flow
- [ ] Cross-file symbol rename guardrails
- [ ] Validation loop: diagnostics/test/build before apply completion

## Workstream D: Collaboration Foundation (Days 36-45)
- [ ] Basic Live Share protocol skeleton
- [ ] Shared terminal sessions
- [ ] Comment/annotation foundation
- [ ] Session presence + conflict handling minimum viable lane

## Program Gates (must pass)
- [ ] Gate 1 (Day 14): top 10 tools + PR CRUD + cache + smoke pass
- [ ] Gate 2 (Day 21): LSP polish trio validated
- [ ] Gate 3 (Day 35): workspace parity path operational
- [ ] Gate 4 (Day 45): collaboration baseline + stability >= 90%

## Tracking Board (single source of truth)
### In Progress
- [ ] A3: Tool result caching

### Next Up
- [ ] A1: execute_command hardening
- [ ] A1: get_code_outline implementation
- [ ] A2: GitHub PR create/list/get path

### Done
- [x] list_directory hardening and crash-path stabilization
- [x] agentic smoke lane recovery and validation

## Evidence Requirements for each closed item
- Code reference (file + line)
- Build/diagnostic status
- Smoke or targeted test output
- Risk note if partial
