# RawrXD 45-Day Parity Finish Plan (v1.2.0-Beta Track)

Date: 2026-04-12
Owner: Core RawrXD Team
Plan Horizon: 45 days

## Mission
Close the highest-value parity gaps against VS Code + GitHub Copilot with a disciplined 45-day execution lane focused on tools, LSP polish, workspace workflows, and release gating.

## Current Baseline
- Feature parity: 55%
- Tool ecosystem: 60%
- LSP/IntelliSense: 70%
- Collaboration: 30%
- Extension ecosystem: 20%
- Cloud/enterprise: 40%

## Success Targets (Day 45)
- Feature parity: >= 75%
- Tool ecosystem: >= 85%
- LSP/IntelliSense: >= 90%
- Collaboration foundation: >= 45%
- Extension ecosystem: >= 30% (foundation only)
- Cloud/enterprise: >= 55%

## Workstreams and Scope

### WS1 - Built-in Tool Completion (22 tools)
Status key: Done / In Progress / Planned

- [x] read_file (Done)
- [x] write_file (Done)
- [x] list_directory (Done)
- [x] search_files (Done)
- [x] codebase_search (Done)
- [x] execute_command hardening (Completed Day 1)
- [x] get_code_outline full implementation (Delivered Day 1)
- [ ] edit_file inline diff integration (In Progress Day 1)
- [ ] terminal_integration full PTY
- [ ] git_operations expanded suite
- [ ] browser_integration (WebView2 headless path)
- [ ] database_tools
- [ ] docker_integration
- [ ] kubernetes_tools
- [ ] api_testing
- [ ] documentation_gen full generation mode
- [ ] test_generation full suite mode
- [ ] refactoring_tools advanced operations
- [ ] performance_profiler integration
- [ ] debugger_integration full DAP support
- [ ] dependency_analysis graph mode
- [ ] security_scanner SAST integration

### WS2 - GitHub PR Toolset (22 tools)
- [ ] create_pull_request
- [ ] review_pull_request
- [ ] merge_pull_request
- [ ] pr_description_gen
- [ ] pr_summary
- [ ] check_status
- [ ] list_prs
- [ ] get_pr_details
- [ ] add_pr_comment
- [ ] resolve_pr_comment
- [ ] request_review
- [ ] pr_check_runs
- [ ] pr_files_changed
- [ ] pr_line_comments
- [ ] pr_draft_status
- [ ] pr_labels
- [ ] pr_assignees
- [ ] pr_milestones
- [ ] pr_linked_issues
- [ ] pr_branch_ops
- [ ] pr_conflict_resolution
- [ ] pr_code_suggestions

### WS3 - LSP/IntelliSense to 90%+
- [ ] code actions depth and quality improvements
- [ ] code lens
- [ ] inlay hints
- [ ] semantic highlighting completion
- [ ] call hierarchy
- [ ] type hierarchy

### WS4 - Copilot Workspace Parity (Core Slice)
- [ ] multi-file edit planning graph
- [ ] workspace-wide safe refactor flow
- [ ] cross-file symbol rename orchestration
- [ ] execution preview + approval UX for multi-file plans

### WS5 - Collaboration Foundation (Beta-safe)
- [ ] basic shared session protocol (text + cursor)
- [ ] shared terminal relay v1
- [ ] shared server/port metadata v1
- [ ] comment threads + annotations v1

### WS6 - Extension and Enterprise Foundations
- [ ] extension API delta map vs VS Code primitives
- [ ] extension host isolation starter architecture
- [ ] SSO/SAML hardening pass
- [ ] audit logging completeness pass
- [ ] policy management validation pass
- [ ] network isolation controls v1

## 45-Day Timeline

### Sprint A (Days 1-7) - Foundation + Top Tool Gaps
- [x] Day 1 kickoff: baseline registry + bridge audit started
- [x] execute_command hardening complete
- [x] get_code_outline shipped
- [ ] edit_file inline diff shipped (In Progress)
- [x] terminal PTY upgrade started
- [ ] release metrics dashboard skeleton

### Sprint B (Days 8-14) - Tool Throughput
- [ ] terminal PTY upgrade complete
- [ ] git_operations expanded suite complete
- [ ] browser_integration complete
- [ ] api_testing complete
- [x] add tool result caching and TTL policy

### Sprint C (Days 15-21) - LSP Polish
- [ ] code lens complete
- [ ] inlay hints complete
- [ ] call hierarchy complete
- [ ] type hierarchy started
- [ ] semantic highlighting closure

### Sprint D (Days 22-28) - Workspace Parity Core
- [ ] multi-file planning graph complete
- [ ] cross-file rename orchestration complete
- [ ] refactor preview + approval flow complete

### Sprint E (Days 29-35) - GitHub PR Tools Slice
- [ ] PR CRUD baseline complete
- [ ] status/checks integration complete
- [ ] diff and line comment paths complete

### Sprint F (Days 36-45) - Stabilize + Beta Gate
- [ ] collaboration foundation v1 complete
- [ ] extension/enterprise foundational slices complete
- [ ] reliability hardening + perf validation
- [ ] v1.2.0-beta release gate review and sign-off

## Critical Dependencies
- WS1 terminal/execute_command security gates WS2 and WS4 automation throughput.
- WS3 hierarchy primitives reduce WS4 multi-file planning risk.
- WS2 check_status depends on CI metadata normalization layer.
- Collaboration features are explicitly time-boxed to foundational v1 only for this 45-day lane.

## Day 1 Started Log (Now)

### Started
- [x] Backlog instantiated in active task tracker.
- [x] Existing implementation/docs baseline checked for tool execution architecture.
- [x] Core source locations confirmed for immediate WS1 work.
- [x] execute_command safety hardening implemented (binary allowlist + destructive safety gate).
- [x] execute_command timeout policy hardened (clamped range + timeout metadata).
- [x] tool result caching + TTL policy implemented in ToolRegistry dispatch.
- [x] get_code_outline implemented and wired (dispatch + schema + symbol extraction).
- [x] get_code_outline upgraded to LSP-first with hierarchical `symbol_tree` output and MASM/INC fallback rules for PROC/STRUCT/MACRO.
- [x] edit_file safety foundation implemented in replace path (preview_only/dry_run + unified_diff + rollback metadata).
- [x] terminal execution upgraded with ConPTY-first path + 512MB circular capture buffer and fallback chain (ConPTY -> term-pipe -> CreateProcess).
- [x] rollback_file tool implemented (latest backup restore, explicit backup_path support, preview_only, and forward backup guard).
- [x] terminal PTY buffer safety foundation implemented (circular output retention + 512MB hard cap telemetry in dynamic terminal manager).
- [x] undo_edit tool alias implemented for autonomous revert loops (latest backup restore + preview diff metadata).
- [x] terminal manager now uses real Windows PowerShell process execution with bounded pipe capture, timeout enforcement, and 20% oldest-log eviction on overflow.
- [x] runtime lane dependency fault `0xC0000135` diagnosed via `dumpbin /dependents` and corrected by building/deploying `RawrXD_Titan.dll` into launch lane (`build/dist`), with clean isolated probe launch (`rawrxd_probe.exe`).

### Evidence Anchors
- d:/TOOL_REGISTRY_IMPLEMENTATION.md
- d:/P0_ITEM_1_TOOL_EXECUTION_UX_DIAGNOSIS.md
- d:/rawrxd/src/agentic/ToolRegistry.cpp
- d:/rawrxd/src/agentic/AgentToolHandlers.cpp
- d:/rawrxd/src/win32app/Win32IDE_AgenticBridge.cpp
- d:/rawrxd/src/agentic/AgenticChatSession.cpp

## Operating Cadence
- Daily: 15-minute unblock + progress update against this file.
- Every 3 days: parity score refresh and risk register update.
- Weekly: release-gate snapshot with hard metrics (latency, stability, pass rate, parity score).

## Definition of Done (Per Item)
- Code merged with tests.
- Smoke path passes in strict mode when applicable.
- Telemetry added for failures and latency.
- Docs updated for operator usage and rollback path.

## Risk Register (Initial)
- R1: Tool surface area is large and can create quality dilution.
  - Mitigation: prioritize top 10 impact tools first; freeze low-value tools until Sprint F.
- R2: Parallel/speculative execution could destabilize UX if streaming injection remains weak.
  - Mitigation: gate with feature flags and staged rollout.
- R3: Collaboration scope can consume full roadmap.
  - Mitigation: strict v1 foundation only in this 45-day lane.

## Immediate Next Actions (Next 24h)
- [x] Add explicit security policy checks and command allowlist path for execute_command.
- [x] Implement get_code_outline against current symbol pipeline.
- [x] Design edit_file diff path with rollback metadata.
- [x] Implement rollback_file to close edit safety loop.
- [x] Implement undo_edit alias to support agent self-correction flows.
- [ ] Add first parity scorecard snapshot in docs/reports.

## Execution Handoff Checkpoints (Next 72h)

### Checkpoint H1 (T+24h)
- Owner: Tooling Lane
- Deliverables:
  - `get_code_outline` handler landed with LSP-first path + hierarchical tree + parser fallback (including MASM/INC scanner fallback)
  - telemetry counters for outline success/failure + latency
  - strict compile pass on touched targets
- Exit Criteria:
  - targeted smoke call returns non-empty symbols for C++ and MASM samples

### Checkpoint H2 (T+48h)
- Owner: Editing Lane
- Deliverables:
  - `edit_file` shadow-buffer + rollback metadata schema
  - unified diff payload emitted for preview UX
  - destructive write path guarded by approval state flag
- Exit Criteria:
  - rollback restores original content in fault-injection test

### Checkpoint H3 (T+72h)
- Owner: Program Lane
- Deliverables:
  - first parity scorecard in `docs/reports/`
  - Sprint A burndown refresh with updated checkboxes
  - risk register refresh (R1-R3) with current status
- Exit Criteria:
  - scorecard includes parity delta and blocker list with owners
