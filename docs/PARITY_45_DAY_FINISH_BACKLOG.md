# RawrXD 45-Day Parity Finish Backlog

Status: ACTIVE (started 2026-04-12)
Owner: Core RawrXD engineering lane
Goal: Move from ~55% parity to a shippable ~75% parity baseline in 45 days.

## Operating Rules
1. No P0 deferrals without blocker, owner, and date.
2. Every completed item must include evidence: code reference + smoke/test proof.
3. Scope lock for 45 days: prioritize parity closure over new net features.
4. Keep Qt-free and avoid adding new dependencies unless explicitly approved.

## Master Priority Stack
1. P0: Tool ecosystem closure (highest leverage).
2. P0: Copilot Workspace parity foundation (multi-file planning/edit loop).
3. P1: LSP polish (code lens, inlay hints, call/type hierarchy).
4. P1: GitHub PR tools (minimum viable lifecycle).
5. P2: Collaboration foundation.
6. P2: Extension ecosystem minimum viability.
7. P2: Cloud/enterprise parity floor.

## 45-Day Plan (Everything)

### Stream A - Built-in Tools (22 total, target 90%+)
Status: IN PROGRESS

Done baseline (keep green):
- [x] read_file
- [x] write_file
- [x] list_directory (hardened)
- [x] search_files
- [x] codebase_search

A1. Security and execution hardening:
- [~] execute_command hardening (allowlist, timeout, output caps, path guards)
- [ ] terminal_integration PTY parity (stdin/stdout streaming, cancel)

A2. IDE intelligence tools:
- [ ] get_code_outline full symbol model
- [ ] edit_file inline diff and patch-preview workflow
- [ ] refactoring_tools advanced operations set

A3. Developer runtime tools:
- [ ] git_operations full suite (status, diff, stage, commit, branch, rebase-safe ops)
- [ ] debugger_integration full DAP session support
- [ ] performance_profiler integration (CPU + timeline hooks)

A4. Platform integration tools:
- [ ] browser_integration (headless WebView2 lane)
- [ ] database_tools (query + schema introspection)
- [ ] docker_integration (container lifecycle)
- [ ] kubernetes_tools (cluster/context/safe apply)
- [ ] api_testing (REST + GraphQL flows)

A5. Engineering productivity tools:
- [ ] documentation_gen full generation path
- [ ] test_generation full suite generation path
- [ ] dependency_analysis graph + hotspot view
- [ ] security_scanner SAST integration

Acceptance gate A:
- [ ] 18/22 tools pass deterministic smoke tests
- [ ] No crash on malformed tool args
- [ ] 95%+ tool result schema compliance

### Stream B - GitHub PR Tooling (22 total, target 70% in 45 days)
Status: NOT STARTED

B1. MVP lifecycle (must-have):
- [ ] create_pull_request
- [ ] get_pr_details
- [ ] list_prs
- [ ] check_status
- [ ] pr_files_changed
- [ ] add_pr_comment
- [ ] resolve_pr_comment

B2. Workflow enrichments:
- [ ] review_pull_request
- [ ] merge_pull_request
- [ ] pr_description_gen
- [ ] pr_summary
- [ ] request_review
- [ ] pr_check_runs
- [ ] pr_line_comments

B3. Metadata/ops:
- [ ] pr_draft_status
- [ ] pr_labels
- [ ] pr_assignees
- [ ] pr_milestones
- [ ] pr_linked_issues
- [ ] pr_branch_ops

B4. Advanced:
- [ ] pr_conflict_resolution
- [ ] pr_code_suggestions

Acceptance gate B:
- [ ] End-to-end PR create -> review -> merge works in smoke lane
- [ ] Comment threading and resolution flow is stable

### Stream C - AI Core to 95%
Status: IN PROGRESS

C1. Tool-calling production wiring:
- [~] Connect existing framework to all built-in/GitHub tool handlers
- [ ] Add tool result caching and dedupe
- [ ] Add tool timeout/retry policy per tool risk class

C2. Speculative decoding:
- [ ] Replace stub with production path
- [ ] Add correctness fallback if speculation diverges
- [ ] Add perf counters: acceptance rate, rollback ratio, TPS lift

C3. Copilot Workspace parity foundation:
- [~] Multi-file edit planning graph (task decomposition + dependency ordering)
- [ ] Cross-file patch preview/approval flow
- [ ] Workspace-wide refactor pass with rollback on fail

Acceptance gate C:
- [ ] Workspace multi-file task closes with plan + diff + tests + summary
- [ ] Speculative decoding measurable TPS improvement with stable quality

### Stream D - LSP/IntelliSense to 95%
Status: NOT STARTED

- [ ] Rich code actions
- [ ] Code lens
- [ ] Inlay hints
- [ ] Semantic highlighting completion
- [ ] Call hierarchy
- [ ] Type hierarchy

Acceptance gate D:
- [ ] LSP parity smoke suite passes across C++, JS/TS, and one extra language lane

### Stream E - Collaboration Foundation
Status: NOT STARTED

- [ ] Basic Live Share protocol skeleton
- [ ] Shared terminal sessions
- [ ] Shared server sessions
- [ ] Code comments/annotations threading
- [ ] Pair-programming AI session handoff base

Acceptance gate E:
- [ ] Two-client collaboration demo (edit + terminal + comments)

### Stream F - Extension Ecosystem Floor
Status: NOT STARTED

- [ ] Extension API hardening + docs
- [ ] Extension host isolation basics
- [ ] Marketplace bootstrap (internal catalog + install path)
- [ ] Settings sync MVP
- [ ] Language extension loading baseline

Acceptance gate F:
- [ ] Install/enable/disable cycle stable for test extensions

### Stream G - Cloud/Enterprise Floor
Status: NOT STARTED

- [ ] SSO/SAML production wiring
- [ ] Audit logging completeness + tamper-evident checks
- [ ] Network isolation controls hardening
- [ ] Knowledge base indexing MVP
- [ ] Admin dashboard MVP endpoints + UI shell

Acceptance gate G:
- [ ] Enterprise smoke pack passes core policy/auth/audit scenarios

## 45-Day Schedule (Critical Path)

### Days 1-14 (Phase 1 Tool Ecosystem)
- [~] Day 1: Backlog lock + acceptance gates + baseline tool contract tests
- [ ] Days 2-4: execute_command hardening + terminal PTY parity
- [ ] Days 5-8: get_code_outline + edit_file inline diff flow
- [ ] Days 9-11: git_operations + documentation/test generation upgrades
- [ ] Days 12-14: GitHub PR MVP lifecycle tools

### Days 15-21 (Phase 2 LSP Polish)
- [ ] Days 15-16: code lens
- [ ] Days 17-18: inlay hints
- [ ] Days 19-21: call/type hierarchy + semantic highlight closure

### Days 22-35 (Phase 3 Workspace Parity)
- [~] Days 22-24: multi-file planning graph completion
- [ ] Days 25-29: multi-file patch + approve/reject UI flow
- [ ] Days 30-35: workspace refactor + rollback + confidence checks

### Days 36-45 (Phase 4 Collaboration Foundation)
- [ ] Days 36-39: live session handshake + shared terminal baseline
- [ ] Days 40-42: shared comments/annotations
- [ ] Days 43-45: stabilization pass + parity gate rehearsal

## Day 1 Start Log (Started Now)
- [x] Consolidated scattered parity docs into one execution backlog.
- [x] Locked priority order and acceptance criteria.
- [~] Started Stream A/C kickoff items:
  - execute_command hardening specification and test contract
  - multi-file planning graph completion scope
- [ ] Next immediate code task: implement execute_command guardrails and add tests.

## Weekly Delivery Rhythm
- Monday: Commit scope and acceptance criteria for the week.
- Tuesday-Thursday: Implementation and incremental smoke checks.
- Friday: Parity gate report (pass/fail + evidence links + risk log).
- Saturday: Recovery buffer for slipped items.
- Sunday: Plan refresh for next week.

## Completion Definition (Day 45)
- [ ] Feature parity >= 75% for v1.2.0-beta objective.
- [ ] Tool ecosystem >= 90% targeted subset coverage.
- [ ] AI core >= 90% with Workspace foundation operational.
- [ ] LSP >= 90% practical parity.
- [ ] Collaboration foundation demonstrable in two-client smoke test.
- [ ] Release readiness report published with open risks and owners.
