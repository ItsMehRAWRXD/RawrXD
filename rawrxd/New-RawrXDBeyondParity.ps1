#requires -Version 7.0
<#
RawrXD Beyond-Parity Generator
Purpose:
  Generate the implementation/certification surface required for RawrXD IDE
  to progress beyond conventional AI coding assistants.

RULE:
  Missing implementation is PENDING/FAIL — never PASS.
  No stubs, fake tool results, simulated inference, or hardcoded success.
#>

[CmdletBinding()]
param(
    [string]$RepoRoot = 'F:\~dev\rawrxd',
    [string]$RawrExe  = 'C:\Users\Garrett\rawrxd\bin\rawr.exe',
    [string]$Model    = 'qwen2.5-coder:1.5b-base',
    [switch]$Generate
)

$ErrorActionPreference = 'Stop'

$Spec = [ordered]@{

    # ─────────────────────────────────────────────────────────────
    # 00 — FOUNDATION
    # ─────────────────────────────────────────────────────────────
    FOUNDATION = [ordered]@{
        Gate = 'RAWRXD_FOUNDATION_001'
        Requirements = @(
            'Local model loading by GGUF path'
            'Ollama manifest -> blob resolution without relocation'
            'Streaming token generation'
            'Cancellation'
            'Deterministic error propagation'
            'No fake-success fallback'
            'Runtime telemetry'
        )
    }

    # ─────────────────────────────────────────────────────────────
    # 01 — RESPONSE AGENT
    # ─────────────────────────────────────────────────────────────
    RESPONSE_AGENT = [ordered]@{
        Gate = 'RAWRXD_RESPONSE_CODED_AGENT_001'
        Requirements = @(
            'USER -> MODEL'
            'MODEL -> optional structured TOOL request'
            'Tool request validated by authority'
            'Real tool execution'
            'Observation returned to model'
            'MODEL -> FINAL RESPONSE'
            'STOP after response'
            'No autonomous background execution'
        )
    }

    # ─────────────────────────────────────────────────────────────
    # 02 — SESSION
    # ─────────────────────────────────────────────────────────────
    SESSION = [ordered]@{
        Gate = 'RAWRXD_SESSION_AUTHORITY_001'
        Requirements = @(
            'Persistent conversation history'
            'System/user/assistant/tool roles'
            'Context-window accounting'
            'Token-budget management'
            'Conversation truncation/summarization'
            'Tool observations retained'
            'Cancellation-safe session state'
        )
    }

    # ─────────────────────────────────────────────────────────────
    # 03 — TOOL AUTHORITY
    # ─────────────────────────────────────────────────────────────
    TOOL_AUTHORITY = [ordered]@{
        Gate = 'RAWRXD_TOOL_AUTHORITY_001'
        Requirements = @(
            'Named tool registry'
            'Structured arguments'
            'Per-tool authorization'
            'Read/write distinction'
            'Workspace boundary enforcement'
            'No arbitrary shell by default'
            'Exit-code capture'
            'stdout/stderr capture'
            'Timeout'
            'Cancellation'
            'Audit receipt'
        )
    }

    # ─────────────────────────────────────────────────────────────
    # 04 — FILESYSTEM
    # ─────────────────────────────────────────────────────────────
    FILESYSTEM = [ordered]@{
        Gate = 'RAWRXD_FILESYSTEM_AGENT_001'
        Requirements = @(
            'List files'
            'Read file'
            'Read range'
            'Search text'
            'Search regex'
            'Find files'
            'Workspace-relative canonical paths'
            'Write file with authority'
            'Patch exact ranges'
            'Create file'
            'Delete only with explicit authority'
        )
    }

    # ─────────────────────────────────────────────────────────────
    # 05 — CODE INDEX
    # ─────────────────────────────────────────────────────────────
    CODE_INDEX = [ordered]@{
        Gate = 'RAWRXD_CODE_INDEX_001'
        Requirements = @(
            'Repository enumeration'
            'Language detection'
            'Symbol extraction'
            'Definition lookup'
            'Reference lookup'
            'Incremental invalidation'
            'Relevant-context retrieval'
            'No mandatory cloud dependency'
        )
    }

    # ─────────────────────────────────────────────────────────────
    # 06 — EDIT ENGINE
    # ─────────────────────────────────────────────────────────────
    EDIT_ENGINE = [ordered]@{
        Gate = 'RAWRXD_EDIT_AUTHORITY_001'
        Requirements = @(
            'Exact patch application'
            'Multi-file transaction'
            'Preimage verification'
            'Reject stale patch'
            'Diff preview'
            'Rollback'
            'Concurrent-writer detection'
            'Do not absorb unrelated worktree changes'
        )
    }

    # ─────────────────────────────────────────────────────────────
    # 07 — TERMINAL
    # ─────────────────────────────────────────────────────────────
    TERMINAL = [ordered]@{
        Gate = 'RAWRXD_TERMINAL_AUTHORITY_001'
        Requirements = @(
            'Explicit command authority'
            'Working-directory control'
            'Environment control'
            'stdout/stderr streaming'
            'Exit status'
            'Timeout'
            'Cancellation'
            'Process-tree termination'
            'No implicit unrestricted shell'
        )
    }

    # ─────────────────────────────────────────────────────────────
    # 08 — BUILD
    # ─────────────────────────────────────────────────────────────
    BUILD = [ordered]@{
        Gate = 'RAWRXD_BUILD_AGENT_001'
        Requirements = @(
            'Discover configured build system'
            'Invoke real compiler/build'
            'Capture diagnostics'
            'Associate errors with files/lines'
            'Return diagnostics to model'
            'Rebuild after authorized edit'
            'Never convert build failure into PASS'
        )
    }

    # ─────────────────────────────────────────────────────────────
    # 09 — TEST
    # ─────────────────────────────────────────────────────────────
    TEST = [ordered]@{
        Gate = 'RAWRXD_TEST_AGENT_001'
        Requirements = @(
            'Discover tests'
            'Run selected test'
            'Run relevant tests'
            'Capture failure output'
            'Return failures to model'
            'Re-run after repair'
            'Receipt uses actual process result'
        )
    }

    # ─────────────────────────────────────────────────────────────
    # 10 — DIAGNOSTICS
    # ─────────────────────────────────────────────────────────────
    DIAGNOSTICS = [ordered]@{
        Gate = 'RAWRXD_DIAGNOSTICS_001'
        Requirements = @(
            'Compiler diagnostics'
            'Runtime failure capture'
            'Crash/exit-code reporting'
            'Model runtime diagnostics'
            'Tool failure diagnostics'
            'Source-location linking'
        )
    }

    # ─────────────────────────────────────────────────────────────
    # 11 — GIT
    # ─────────────────────────────────────────────────────────────
    GIT = [ordered]@{
        Gate = 'RAWRXD_GIT_AGENT_001'
        Requirements = @(
            'status'
            'diff'
            'log'
            'show'
            'branch inspection'
            'Concurrent-writer protection'
            'Explicit authority before mutation'
            'No automatic commit/push without authority'
        )
    }

    # ─────────────────────────────────────────────────────────────
    # 12 — PLAN
    # ─────────────────────────────────────────────────────────────
    PLAN = [ordered]@{
        Gate = 'RAWRXD_PLAN_AGENT_001'
        Requirements = @(
            'Convert request into bounded steps'
            'Identify required evidence'
            'Select tools'
            'Track completed/pending steps'
            'Re-plan from real observations'
            'Stop when requested objective is satisfied'
            'No invented completion'
        )
    }

    # ─────────────────────────────────────────────────────────────
    # 13 — CODE AGENT
    # ─────────────────────────────────────────────────────────────
    CODE_AGENT = [ordered]@{
        Gate = 'RAWRXD_CODE_AGENT_001'
        Requirements = @(
            'Understand request'
            'Retrieve relevant code'
            'Form implementation plan'
            'Produce authorized edits'
            'Build'
            'Inspect diagnostics'
            'Repair'
            'Test'
            'Report actual state'
        )
    }

    # ─────────────────────────────────────────────────────────────
    # 14 — DEBUG AGENT
    # ─────────────────────────────────────────────────────────────
    DEBUG_AGENT = [ordered]@{
        Gate = 'RAWRXD_DEBUG_AGENT_001'
        Requirements = @(
            'Reproduce failure'
            'Collect evidence'
            'Form hypothesis'
            'Inspect relevant implementation'
            'Apply authorized repair'
            'Re-run reproduction'
            'Reject repair if evidence does not improve'
        )
    }

    # ─────────────────────────────────────────────────────────────
    # 15 — ASK AGENT
    # ─────────────────────────────────────────────────────────────
    ASK_AGENT = [ordered]@{
        Gate = 'RAWRXD_ASK_AGENT_001'
        Requirements = @(
            'Read-only'
            'Repository-aware'
            'Can retrieve definitions/references'
            'Can inspect Git history'
            'Cannot mutate workspace'
            'Answers grounded in retrieved evidence'
        )
    }

    # ─────────────────────────────────────────────────────────────
    # 16 — ORCHESTRATION
    # ─────────────────────────────────────────────────────────────
    ORCHESTRATION = [ordered]@{
        Gate = 'RAWRXD_ORCHESTRATION_001'
        Requirements = @(
            'Bounded task decomposition'
            'Independent worker contexts'
            'Tool authority inherited, never expanded'
            'Result aggregation'
            'Conflict detection'
            'No duplicate writers to same path'
            'Final verifier'
        )
    }

    # ─────────────────────────────────────────────────────────────
    # 17 — IDE CHAT
    # ─────────────────────────────────────────────────────────────
    IDE_CHAT = [ordered]@{
        Gate = 'RAWRXD_IDE_CHAT_001'
        Requirements = @(
            'Prompt entry'
            'Streaming response'
            'Cancel generation'
            'Conversation history'
            'Tool-call visualization'
            'Tool result visualization'
            'File references'
            'Diagnostic references'
            'Apply/reject edits'
            'No GUI-only fake chat'
        )
    }

    # ─────────────────────────────────────────────────────────────
    # 18 — INLINE CODE
    # ─────────────────────────────────────────────────────────────
    INLINE_CODE = [ordered]@{
        Gate = 'RAWRXD_INLINE_CODE_001'
        Requirements = @(
            'Selection -> model'
            'Current file context'
            'Generate replacement'
            'Preview diff'
            'Accept/reject'
            'Undo'
        )
    }

    # ─────────────────────────────────────────────────────────────
    # 19 — COMPLETION
    # ─────────────────────────────────────────────────────────────
    COMPLETION = [ordered]@{
        Gate = 'RAWRXD_COMPLETION_001'
        Requirements = @(
            'Cursor-position context'
            'Prefix/suffix context'
            'Low-latency generation'
            'Cancellation on edit'
            'Accept partial/full suggestion'
            'Local model provider'
        )
    }

    # ─────────────────────────────────────────────────────────────
    # 20 — CONTEXT ENGINE
    # ─────────────────────────────────────────────────────────────
    CONTEXT_ENGINE = [ordered]@{
        Gate = 'RAWRXD_CONTEXT_ENGINE_001'
        Requirements = @(
            'Current file'
            'Selection'
            'Open files'
            'Diagnostics'
            'Git diff'
            'Relevant repository symbols'
            'Explicit attached files'
            'Token-budget prioritization'
        )
    }

    # ─────────────────────────────────────────────────────────────
    # 21 — MODEL ROUTER
    # ─────────────────────────────────────────────────────────────
    MODEL_ROUTER = [ordered]@{
        Gate = 'RAWRXD_MODEL_ROUTER_001'
        Requirements = @(
            'GGUF path'
            'Ollama reference'
            'Deep2 local runtime'
            'Per-task model selection'
            'Capability metadata'
            'Context limits'
            'No required external service'
        )
    }

    # ─────────────────────────────────────────────────────────────
    # 22 — LONG TASK
    # ─────────────────────────────────────────────────────────────
    LONG_TASK = [ordered]@{
        Gate = 'RAWRXD_LONG_TASK_AGENT_001'
        Requirements = @(
            'Explicit user-started task only'
            'Persistent task state'
            'Checkpoint after tool operations'
            'Bounded iteration budget'
            'Cancellation'
            'Failure state'
            'No fake completion'
            'Final evidence summary'
        )
    }

    # ─────────────────────────────────────────────────────────────
    # 23 — SAFETY / AUTHORITY
    # ─────────────────────────────────────────────────────────────
    AUTHORITY = [ordered]@{
        Gate = 'RAWRXD_AGENT_AUTHORITY_001'
        Requirements = @(
            'READ authority'
            'WRITE authority'
            'BUILD authority'
            'TEST authority'
            'GIT mutation authority'
            'PROCESS authority'
            'NETWORK authority'
            'Per-task capability set'
            'Default deny'
        )
    }

    # ─────────────────────────────────────────────────────────────
    # 24 — RECEIPTS
    # ─────────────────────────────────────────────────────────────
    RECEIPTS = [ordered]@{
        Gate = 'RAWRXD_AGENT_RECEIPTS_001'
        Requirements = @(
            'Model identity'
            'Resolved model path'
            'Prompt turn count'
            'Tool requests'
            'Authority decisions'
            'Real tool outputs'
            'Files changed'
            'Build result'
            'Test result'
            'Fallback count'
            'Final verdict'
        )
    }

    # ─────────────────────────────────────────────────────────────
    # 25 — BEYOND-PARITY CERT
    # ─────────────────────────────────────────────────────────────
    BEYOND_PARITY = [ordered]@{
        Gate = 'RAWRXD_BEYOND_PARITY_001'
        Requirements = @(
            'Local inference works'
            'Response agent works'
            'Repository context works'
            'Read tools work'
            'Authorized edits work'
            'Build/test repair works'
            'IDE chat uses same agent core'
            'Completion works'
            'Debug mode works'
            'Ask mode is read-only'
            'Code mode performs verified work'
            'Long task is bounded/cancellable'
            'No required cloud inference'
            'No stub fallback'
            'No fake receipts'
        )
    }
}

function Write-Header {
    param([string]$Text)
    Write-Host "`n============================================================"
    Write-Host $Text
    Write-Host "============================================================"
}

function Test-RequirementSurface {
    param([string]$Requirement)

    # This function intentionally does NOT infer PASS from filenames.
    # It reports UNKNOWN until runtime/source evidence proves implementation.
    [pscustomobject]@{
        Requirement = $Requirement
        Status      = 'UNKNOWN'
        Evidence    = ''
    }
}

function New-GateTemplate {
    param(
        [string]$Name,
        [hashtable]$Definition
    )

    $gateDir = Join-Path $RepoRoot 'receipts'
    $gateDir = Join-Path $gateDir $Definition.Gate

    if (-not (Test-Path $gateDir)) {
        New-Item -ItemType Directory -Path $gateDir -Force | Out-Null
    }

    $path = Join-Path $gateDir 'receipt.template.ini'

    $lines = @(
        "GATE=$($Definition.Gate)"
        "COMPONENT=$Name"
        "VERDICT=PENDING"
        "STUB_FALLBACKS=UNMEASURED"
        "FAKE_RESULTS=FORBIDDEN"
        "MODEL=$Model"
        ""
    )

    $i = 0
    foreach ($requirement in $Definition.Requirements) {
        ++$i
        $key = ('REQ_{0:D3}' -f $i)
        $escaped = $requirement.Replace("`r",' ').Replace("`n",' ')
        $lines += "$key=$escaped"
        $lines += "${key}_STATUS=PENDING"
        $lines += "${key}_EVIDENCE="
    }

    $lines += ''
    $lines += 'VERDICT=PENDING'

    Set-Content -LiteralPath $path -Value $lines -Encoding UTF8
    return $path
}

function Show-Plan {
    Write-Header 'RawrXD Beyond-Parity Implementation Matrix'

    foreach ($entry in $Spec.GetEnumerator()) {
        Write-Host "`n[$($entry.Key)] $($entry.Value.Gate)"

        foreach ($req in $entry.Value.Requirements) {
            Write-Host "  [ ] $req"
        }
    }
}

function Test-Preflight {
    Write-Header 'PRE-FLIGHT'

    if (-not (Test-Path $RepoRoot)) {
        throw "Repository does not exist: $RepoRoot"
    }

    Set-Location $RepoRoot

    $head = (git rev-parse HEAD 2>$null)
    $staged = @(git diff --cached --name-only 2>$null)

    Write-Host "REPO=$RepoRoot"
    Write-Host "HEAD=$head"
    Write-Host "STAGED_COUNT=$($staged.Count)"
    Write-Host "RAWR_EXE_EXISTS=$(Test-Path $RawrExe)"
    Write-Host "MODEL=$Model"

    if ($staged.Count -ne 0) {
        throw 'HOLD: staged changes already exist. Refusing to absorb another writer.'
    }
}

function New-AllGateTemplates {
    Write-Header 'GENERATING CERTIFICATION TEMPLATES'

    foreach ($entry in $Spec.GetEnumerator()) {
        $path = New-GateTemplate `
            -Name $entry.Key `
            -Definition $entry.Value

        Write-Host "GENERATED=$path"
    }
}

function Write-MasterManifest {
    $manifest = Join-Path $RepoRoot 'RAWRXD_BEYOND_PARITY_MANIFEST.md'

    $content = New-Object System.Collections.Generic.List[string]

    $content.Add('# RawrXD Beyond-Parity Implementation Manifest')
    $content.Add('')
    $content.Add('Generated requirements are not proof of implementation.')
    $content.Add('')
    $content.Add('A gate remains PENDING until runtime/source evidence proves every required property.')
    $content.Add('')

    foreach ($entry in $Spec.GetEnumerator()) {
        $content.Add("## $($entry.Key)")
        $content.Add('')
        $content.Add("Gate: ``$($entry.Value.Gate)``")
        $content.Add('')

        foreach ($req in $entry.Value.Requirements) {
            $content.Add("- [ ] $req")
        }

        $content.Add('')
    }

    Set-Content -LiteralPath $manifest -Value $content -Encoding UTF8

    Write-Host "MANIFEST=$manifest"
}

function Show-ExecutionOrder {
    Write-Header 'IMPLEMENTATION ORDER'

    @'
PHASE 0  FOUNDATION
        ↓
PHASE 1  RESPONSE_AGENT
        ↓
PHASE 2  SESSION + TOOL_AUTHORITY
        ↓
PHASE 3  FILESYSTEM + GIT + CONTEXT_ENGINE
        ↓
PHASE 4  CODE_INDEX
        ↓
PHASE 5  EDIT_ENGINE
        ↓
PHASE 6  TERMINAL + BUILD + TEST + DIAGNOSTICS
        ↓
PHASE 7  ASK + PLAN + CODE + DEBUG
        ↓
PHASE 8  IDE_CHAT + INLINE_CODE + COMPLETION
        ↓
PHASE 9  ORCHESTRATION + LONG_TASK
        ↓
PHASE 10 RECEIPTS + AUTHORITY
        ↓
RAWRXD_BEYOND_PARITY_001
'@ | Write-Host
}

Test-Preflight
Show-Plan
Show-ExecutionOrder

if ($Generate) {
    New-AllGateTemplates
    Write-MasterManifest

    Write-Header 'GENERATION COMPLETE'
    Write-Host 'Templates generated.'
    Write-Host 'NO IMPLEMENTATION HAS BEEN CLAIMED.'
    Write-Host 'NO GATE HAS BEEN MARKED PASS.'
    Write-Host 'Fill each requirement with real source + runtime evidence.'
}
else {
    Write-Host "`nDry run only."
    Write-Host "Use -Generate to create the manifest and receipt templates."
}
