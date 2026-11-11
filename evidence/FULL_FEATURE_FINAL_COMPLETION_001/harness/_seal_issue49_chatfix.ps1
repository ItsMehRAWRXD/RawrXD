$ErrorActionPreference = 'Stop'
$e6cf = 'E6CF5BD2B23638B046926F301997926BD35B1524CD3D58B59A75A24946466A3E'
$tip = 'F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\candidates\tip_final_integ_008\RawrXD-Win32IDE-Native-Ext.exe'
$tipSha = (Get-FileHash -LiteralPath $tip -Algorithm SHA256).Hash
if ($tipSha -ne $e6cf) { throw "ABORT SHA_DRIFT tip=$tipSha" }

$harnessReceipt = 'F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\artifacts\issue49_integ008_chatfix\ISSUE49_PRODUCT_FINAL_TIP002_RECEIPT.txt'
$runlog = (Get-ChildItem 'F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\artifacts\issue49_integ008_chatfix\issue49_product_final_tip002_*.txt' |
  Sort-Object LastWriteTime -Descending | Select-Object -First 1).FullName
$hr = Get-Content -LiteralPath $harnessReceipt -Raw

function Get-Field([string]$text, [string]$key) {
  $m = [regex]::Match($text, "(?m)^$([regex]::Escape($key))=(.*)$")
  if ($m.Success) { return $m.Groups[1].Value.Trim() }
  return ''
}

$hits = Get-Field $hr 'REQUIRED_PASS_HITS'
$verdict = Get-Field $hr 'ISSUE49_VERDICT'
$s05 = Get-Field $hr 'S_05_AGENT_PROMPT'
$spawned = Get-Field $hr 'DEEP2_AGENTIC_LOOP_SPAWNED'
$agentSession = Get-Field $hr 'AgentSession_IN_EXE'
$chatInput = if ($s05 -match '^PASS') { 'PASS' } else { 'FAIL' }
$agentic = if ($spawned -eq '1') { 'PASS' } else { 'BLOCKED' }
$missingLink = 'H57_AgentSession_NOT_LINKED_IN_NATIVE_EXT;WM_COMMAND_4106_4100_FALSE;IDE_EXIT_-1_AFTER_AGENTIC_CMDS;deep2_agentic_loop_BESIDE_BUT_SPAWNED=0'

$asof = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
$receiptPath = 'F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\INTEG008_ISSUE49_PRODUCT_FINAL_RECEIPT.md'

$body = @"
# INTEG008_ISSUE49_PRODUCT_FINAL_RECEIPT - G8_ISSUE49_PRODUCT_FINAL

ASOF_UTC=$asof
MOTD_ACK=1
SEALED_UTC=$asof

``````
GATE=G8_ISSUE49_PRODUCT_FINAL
CANDIDATE=INTEG_008
CONTROLLING_TIP=CC79
AUTHORITATIVE_CANDIDATE_SHA256=$e6cf
MEASURED_EXE_SHA256=$tipSha
EXE_AT_PREFLIGHT=$tip
EXE_SIZE_BYTES=$((Get-Item -LiteralPath $tip).Length)
EXE_MTIME_UTC=$((Get-Item -LiteralPath $tip).LastWriteTimeUtc.ToString('o'))
RESTORE=HELD
RESTORE_SOURCE=F:\rawrxd\build_tip_ext_host_001\bin\RawrXD-Win32IDE-Native-Ext.exe
RESTORE_HASH_CONFIRM=1
POST_HARNESS_SHA_MATCH=1
DISK_DRIFT=0
MID_SESSION_OVERWRITE=0
ABORT=0
HARNESS_EXECUTED=1
HARNESS=F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\harness\issue49_product_final_e6cf_chatfix.ps1
HARNESS_OUTDIR=F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\artifacts\issue49_integ008_chatfix
HARNESS_RUNLOG=$runlog
HARNESS_RECEIPT=$harnessReceipt
CHAT_INPUT=$chatInput
CHAT_PATH=BUSYWAIT_CTRL_ENTER_WM_SETTEXT_FIND_EDIT_1202
S05=$s05
AGENTIC_LOOP=$agentic
AGENTIC_MISSING_LINK=$missingLink
AgentSession_IN_EXE=$agentSession
ISSUE49_E2E=FAIL_CLOSED_PARTIAL_STEPS
ISSUE49_VERDICT=$verdict
RAWRXD_PRODUCT_FINAL_001=NOT_DEMONSTRATED
REQUIRED_PASS_HITS=$hits
REQUEUE=0
FOUR_PANEL=PRIOR_SEAL_ON_E6CF_NOT_REQUEUED
CROSS_SHA_PASS_INHERITANCE=0
NO_INHERIT_FROM_1046C2B8=1
TIP_007_ACBE_UNTOUCHED=1
TIP_MOVE_AUTHORIZED=0
A4F_IMMUTABLE=1
PROMOTE=0
CERTIFIED=0
PRODUCT_PASS=0
TIP_CLIMB=HOLD
ENGINEERING_MATURITY=82%_UNCHANGED
INVENT_PASS=0
NOT_RUN_NE_PASS=1
FROZEN=1
STOP_OVERWRITE=1
LS_IN_PANE=FAIL_SECONDARY_NOT_DIVERTED
AUTHORITATIVE_HIDDEN_GAP_REGISTER=UNRECONCILED_SPLIT
REGISTER_AUTHORITY_PROPOSAL=FULL_FEATURE_FINAL_COMPLETION_001\HIDDEN_GAP_AUDIT_001\MASTER_DEFECT_REGISTER.md
REGISTER_AUTHORITY_PROPOSAL_NOTE=Propose AUTHORITATIVE=1 after lineage seal to oneshot/audit/final registers; do not delete others.
``````

# Per-step (Issue #49 map) - remesured on E6CF with chatfix harness
S00_CLEAN_CLONE=NOT_RUN_LANE_HARNESS_NOT_CLEAN_MACHINE
S01_LAUNCH=PASS_MAIN_HWND
S02_LOCAL_MODEL_LOAD=MODEL_PATH_PRESENT_LOAD_NOT_PROVEN
S03_GPU_RUNTIME_R9700=NOT_RUN
S04_OPEN_PROJECT=PASS_ARGV_OPEN_FIXTURE
S05_AGENT_PROMPT=$s05
S06_AGENT_READS_PROJECT=BLOCKED_NO_AGENTIC_LOOP_PROCESS
S07_AGENT_REASONING_GPU=NOT_RUN
S08_TOOL_AUTHORITY=BLOCKED_NO_REAL_TOOL_CALL_EVIDENCE
S09_RESULT_REINJECTION=NOT_RUN
S10_REAL_SOURCE_EDIT=NOT_RUN_NO_AGENT_EDIT
S11_BUILD_FAILURE_RECOVERY=NOT_RUN_REQUIRES_AGENT_OWNED_RECOVERY
S11_BUILD_FAILURE_SUBSTRATE_ONLY=PASS_FIXTURE_BUILD_FAIL
S12_MODEL_DIAGNOSES_FAILURE=NOT_RUN
S13_SECOND_EDIT=NOT_RUN
S14_FINAL_BUILD=NOT_RUN
S15_FINAL_TESTS=NOT_RUN
S16_MULTI_AGENT_REVIEW=NOT_RUN_NO_INDEPENDENT_REVIEWER
S17_AGENT_EVIDENCE_REPORT=NOT_RUN
S18_IDE_GIT_COMMIT=NOT_RUN
H57_AGENTSESSION=BLOCKED_NOT_LINKED_IN_NATIVE_EXT
IDE_GIT=NOT_RUN_DEFAULT_NO_COMMIT

BLOCKERS=$missingLink;NO_REAL_TOOL_CALL_EVIDENCE;NO_AGENT_SOURCE_EDIT;NO_AGENT_OWNED_BUILD_RECOVERY;GPU_R9700_NOT_RUN;NO_INDEPENDENT_REVIEWER;ISSUE49_AUTONOMOUS_LOOP_INCOMPLETE

## Disposition
Preflight tip_008 already E6CF (RESTORE=HELD). Issue #49 remesure used busywait Ctrl+Enter chat path; S05 PASS. Agentic loop spawn NOT demonstrated on Native-Ext — exact missing link: AgentSession not linked in EXE (H57); WM_COMMAND 4106/4100 returned False; IDE exited -1; deep2_agentic_loop beside but SPAWNED=0. Hits $hits (was 2/11). Product-final NOT demonstrated. PROMOTE=0 TIP_MOVE_AUTHORIZED=0.
NEXT_GATE=ISSUE49_AGENTSESSION_LINK_OR_NATIVE_EXT_AGENTIC_SPAWN_ON_E6CF
"@

# Fix accidental 6-backtick fences to 3
$body = $body.Replace("``````", '```')
[IO.File]::WriteAllText($receiptPath, $body)

$nextPost = 'F:\rawrxd\evidence\POST_E59D_CANDIDATE_001\NEXT_ACTION.md'
$nextFf = 'F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\NEXT_ACTION.md'
$nextBody = @"
# NEXT_ACTION - Issue #49 active; Freeze Control handoff

ASOF_UTC=$asof

``````
ISSUE49_ACTIVE=1
ISSUE49_SCORE=$hits
CHAT_INPUT=$chatInput
SESSION_LOOP=NOT_DEMONSTRATED
AGENTIC_LOOP=$agentic
AGENTIC_MISSING_LINK=$missingLink
E6CF_RESTORE=HELD
ENGINEERING_MATURITY=82%_UNCHANGED
MAJOR_INTEGRATED_ACCEPTANCE=NOT_DEMONSTRATED
NEXT_MILESTONE=ONE_SHA_11_11
CERTIFIED=0
PROMOTE=0
PRODUCT_PASS=0
TIP_MOVE_AUTHORIZED=0

AUTHORITATIVE_HIDDEN_GAP_REGISTER=UNRECONCILED_SPLIT
REGISTER_AUTHORITY_PROPOSAL=FULL_FEATURE_FINAL_COMPLETION_001\HIDDEN_GAP_AUDIT_001\MASTER_DEFECT_REGISTER.md

RECEIPT=$receiptPath
NEXT_GATE=ISSUE49_AGENTSESSION_LINK_OR_NATIVE_EXT_AGENTIC_SPAWN_ON_E6CF
``````

## Order

1. Keep CHAT_INPUT harness on busywait Ctrl+Enter path (now PASS on E6CF).
2. Unblock agentic loop: link AgentSession into Native-Ext **or** prove alternate spawn path on same SHA E6CF (product rebuild => new SHA + full requeue; no inherit).
3. Remeasure Issue #49 toward 11/11 on one SHA after spawn path exists.
4. LS_IN_PANE remains FAIL secondary — do not divert.
5. Reconcile hidden-gap registers; seal one AUTHORITATIVE=1 with lineage (do not delete others).
"@
$nextBody = $nextBody.Replace("``````", '```')
[IO.File]::WriteAllText($nextPost, $nextBody)
[IO.File]::WriteAllText($nextFf, $nextBody)

$regStatus = 'F:\rawrxd\evidence\POST_E59D_CANDIDATE_001\AUTHORITATIVE_HIDDEN_GAP_REGISTER_STATUS.md'
$reg = @"
# AUTHORITATIVE_HIDDEN_GAP_REGISTER_STATUS

ASOF_UTC=$asof
MOTD_ACK=1

``````
AUTHORITATIVE_HIDDEN_GAP_REGISTER=UNRECONCILED_SPLIT
EXHAUSTIVE_CLOSURE=BLOCKED
PROPOSE_AFTER_RECONCILE=FULL_FEATURE_FINAL_COMPLETION_001\HIDDEN_GAP_AUDIT_001\MASTER_DEFECT_REGISTER.md
PROPOSE_REASON=Deduped H01-H120 / #49/#50 defect register; lineage still required to oneshot+audit+final lanes
AUTHORITATIVE=0
PROMOTE=0
CERTIFIED=0
``````

## Present (none marked sole authority)

| Path | Role |
|------|------|
| ``FULL_FEATURE_ONESHOT_001\MASTER_HIDDEN_GAP_REGISTER.md`` | Oneshot lane absorb (EXACTLY_ONCE / LS_IN_PANE notes) |
| ``FULL_FEATURE_FINAL_COMPLETION_001\MASTER_HIDDEN_GAP_REGISTER_001.md`` | Final-completion lane |
| ``HIDDEN_GAP_AUDIT_001\MASTER_HIDDEN_GAP_REGISTER.md`` | Audit lane |
| ``FULL_FEATURE_FINAL_COMPLETION_001\HIDDEN_GAP_AUDIT_001\MASTER_DEFECT_REGISTER.md`` | Deduped defect register (H01–H120 / #49/#50) — proposed post-reconcile authority |

## Law
Until one register is sealed ``AUTHORITATIVE=1`` with lineage to the others (or explicit supersession), exhaustive hidden-gap closure remains **BLOCKED**. Do not invent a sole authority. Do not silently delete others.
"@
$reg = $reg.Replace("``````", '```')
[IO.File]::WriteAllText($regStatus, $reg)

Write-Host "SEALED=$receiptPath"
Write-Host "CHAT_INPUT=$chatInput"
Write-Host "AGENTIC_LOOP=$agentic"
Write-Host "ISSUE49_HITS=$hits"
Write-Host "EXE_SHA256=$tipSha"
Write-Host "NEXT_GATE=ISSUE49_AGENTSESSION_LINK_OR_NATIVE_EXT_AGENTIC_SPAWN_ON_E6CF"
