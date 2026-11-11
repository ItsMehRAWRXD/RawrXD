# Generates MASTER_HIDDEN_GAP_REGISTER_001.md + CSV — fail-closed, no invented PASS
$ErrorActionPreference = 'Stop'
$outDir = 'F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001'
$mdPath = Join-Path $outDir 'MASTER_HIDDEN_GAP_REGISTER_001.md'
$csvPath = Join-Path $outDir 'MASTER_HIDDEN_GAP_REGISTER_001.csv'
$asof = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
$CC79 = 'CC79F6CDD08F5ECEBB672290CC96F7FEEEA0DA6AB6F8B596E5826C3EA22940C4'
$INTEG = '47451F241262A7F4471D60C3D12454A93EF1C333273BEFF828B9A69F23DC274F'
$TIP004_PRIOR = '69FE3D921FECC3DC66DA9E71901B338A045D706717F00C3B587B3B1BDB1268BB'
$TIP004_LIVE = '35EFA9BAE44AD23F6007AC158E1BF0D6C297A5412C8DEF513434058C6D044351'
$TIP003_LIVE = 'DD60FFB8CFB5133ADC0C6E59124C4E4A199E26F310FD00C6A55EC9F7D8A9497C'
$TIP003_HIST = '0EA05DF722DCF26F9692584EB90CB03E243664363AA318D944FD813BFF7395E2'
$A4F = 'A4F083DFB9CCD1F78036E1CDCDCA9AF881EF10B3E34170B68C4610D51AC6EF4E'
$lane = 'FULL_FEATURE_FINAL_COMPLETION_001'

$rows = New-Object System.Collections.Generic.List[object]
function Add-Row($id,$title,$status,$maps,$sha,$ev,$next) {
  $rows.Add([pscustomobject]@{ID=$id;Title=$title;Status=$status;MapsTo=$maps;ControllingSHA=$sha;EvidencePath=$ev;NextProof=$next}) | Out-Null
}

# --- Titles for H01-H120 ---
$H = @{
H01='Implemented source files excluded from the production CMake target'
H02='Duplicate implementations with only the older version linked'
H03='Stub functions silently replacing production functionality'
H04='Feature flags disabling important components in release builds'
H05='Missing source dependencies concealed by incremental builds'
H06='Stale object files producing apparently successful builds'
H07='Debug and Release configurations behaving differently'
H08='Incorrect compiler definitions or inherited environment variables'
H09='Unresolved symbols hidden behind optional build paths'
H10='Different branches containing incompatible implementations'
H11='Generated headers or resources missing from clean checkout'
H12='Non-reproducible binaries despite identical source revisions'
H13='Menu commands pointing to missing or incorrect handlers'
H14='Toolbar buttons displaying but not executing'
H15='Keyboard shortcuts bypassing the correct command path'
H16='HWND references surviving after window destruction'
H17='Worker threads modifying Win32 controls directly'
H18='Posted messages arriving after session cancellation'
H19='Reentrant window procedures corrupting application state'
H20='Focus switching between panels breaking keyboard input'
H21='Incorrect DPI scaling or panel geometry'
H22='Resize operations destroying or obscuring controls'
H23='Modal dialogs blocking active background operations'
H24='UI thread deadlocks during compiler or model execution'
H25='Unhandled exceptions inside message dispatch'
H26='Window recreation losing application state'
H27='Compiler subprocess inheriting incompatible environment variables (VS_UNICODE_OUTPUT stall)'
H28='Stdout/stderr pipe backpressure causing deadlocks'
H29='Compiler child processes surviving cancellation'
H30='Timeout terminating the parent but not descendants'
H31='Diagnostics parsed incorrectly when paths contain spaces'
H32='Unicode diagnostic text corrupted'
H33='Compiler warnings mistaken for errors'
H34='Duplicate Problems entries from repeated builds'
H35='Old diagnostics remaining after successful rebuild'
H36='Problems click-to-line dispatching without actual navigation'
H37='Incorrect line/column offsets'
H38='Multiple projects mixing diagnostic ownership'
H39='Linker errors missing from Problems'
H40='Failed builds reporting success because artifacts already exist'
H41='Native PE/COFF linker accepting malformed relocations'
H42='Compiler adapter passing while native compiler functionality remains incomplete'
H43='Extension discovery works but activation never executes'
H44='Worker starts without completing IPC handshake'
H45='IPC messages lack framing or size validation'
H46='Extension commands execute on the wrong thread'
H47='Host and worker disagree on protocol version'
H48='Extension crashes terminate the entire IDE'
H49='Unloading leaves callbacks registered'
H50='Reloading creates duplicate commands or subscriptions'
H51='Extension process survives IDE shutdown'
H52='Crashed workers cannot restart cleanly'
H53='Extension filesystem access bypasses permissions'
H54='Extension event handlers block the UI'
H55='Extension state corrupts across projects'
H56='A test extension passes but real extensions fail'
H57='Agent session lifetime not owned by a single controller'
H58='Cancelled agent continues executing tools'
H59='Old tool results injected into a newer conversation'
H60='Model-generated tool calls parsed incorrectly'
H61='Tool permission checks bypassed by alternate entry points'
H62='Agent edits wrong workspace or file'
H63='Partial writes leave corrupted source'
H64='Failed edits cannot be rolled back'
H65='Agent reports build success without executable evidence'
H66='Agent loops indefinitely after repeated failures'
H67='Tool execution blocks model streaming'
H68='Concurrent agents overwrite one another changes'
H69='Agent state cannot recover after application restart'
H70='Review agent approves untested changes'
H71='Git commit includes unrelated modifications'
H72='Agent reports task completion before final tests finish'
H73='Model selector points to wrong model or backend'
H74='Ollama streaming parser mishandles fragmented JSON'
H75='Inference cancellation leaves active GPU work'
H76='Backend shutdown leaks threads or memory'
H77='Model loading succeeds but inference produces invalid output'
H78='GPU offload counters differ from actual executed operations'
H79='Quantized kernels produce incorrect numerical results'
H80='KV-cache rollback corrupts subsequent generations'
H81='Long-context allocation exceeds available VRAM/RAM'
H82='Multi-GPU partitioning causes incorrect tensor placement'
H83='GPU synchronization serializes supposedly parallel execution'
H84='Fallback paths silently execute on CPU'
H85='Driver incompatibility is mistaken for a model defect'
H86='Model switching retains stale tokenizer or sampler state'
H87='GPU device loss cannot be recovered without restarting the IDE'
H88='Benchmark throughput excludes prefill waits or transfers without disclosure'
H89='Model-format and GGUF shard validation accepts corrupt data'
H90='Local-only operation inadvertently depends on external services'
H91='Workspace path traversal through agent or extension tools'
H92='Untrusted model output bypasses tool authorization'
H93='Shell argument handling allows unintended command execution'
H94='Sensitive values leak into logs or crash dumps'
H95='Extension IPC accepts unauthorized commands'
H96='Downloaded or installed extensions lack appropriate validation'
H97='Security-sensitive production paths use placeholder cryptography'
H98='Release binaries depend on undeclared DLLs'
H99='Installer writes outside intended directories'
H100='Uninstall or rollback destroys user data'
H101='Crash recovery replays unsafe or incomplete operations'
H102='Build artifacts or test receipts are accepted without provenance'
H103='GitHub Actions reports success without executing mandatory tests'
H104='LFS or branch divergence leaves the release source incomplete'
H105='Signed artifact differs from the tested executable'
H106='Final release is certified using evidence from multiple SHAs'
H107='LSP handshake succeeds but diagnostics/completion do not work'
H108='GhostText appears but accept/cancel edits the wrong range'
H109='Native browser renders but lacks origin or navigation isolation'
H110='Git operations modify an unintended repository or branch'
H111='Snapshot restoration fails after a partially completed edit'
H112='Settings persist but are not applied to active components'
H113='Feature registry advertises commands with no real backend'
H114='Cross-platform functionality is claimed without native execution'
H115='Performance tests use synthetic kernels instead of real model decode'
H116='Release documentation describes capabilities absent from the binary'
H117='Acceptance tests omit negative and recovery scenarios'
H118='Multiple passing components fail when operated simultaneously'
H119='Test fixtures conceal environment or dependency requirements'
H120='Final product acceptance omits the complete autonomous coding loop'
}

# Default all H to INVESTIGATE
1..120 | ForEach-Object {
  $id = 'H{0:D2}' -f $_
  if ($_ -ge 100) { $id = 'H{0}' -f $_ }
  # Fix H01-H09 padding: H01 style
  $id = 'H' + $_.ToString('00')
  if ($_ -ge 100) { $id = 'H' + $_ }
  Add-Row $id $H[$id] 'INVESTIGATE' $id $CC79 'parent_H01-H120_register' 'Static/runtime audit per AUDIT_LAW; no invent CONFIRMED'
}

# Helper to update existing row by ID
function Set-Row($id,$status,$maps,$sha,$ev,$next,$title=$null) {
  $r = $rows | Where-Object { $_.ID -eq $id } | Select-Object -First 1
  if (-not $r) {
    Add-Row $id $(if($title){$title}else{$id}) $status $maps $sha $ev $next
    return
  }
  $r.Status = $status
  if ($maps) { $r.MapsTo = $maps }
  if ($sha) { $r.ControllingSHA = $sha }
  if ($ev) { $r.EvidencePath = $ev }
  if ($next) { $r.NextProof = $next }
  if ($title) { $r.Title = $title }
}

# === Evidence-backed overrides (absorb FIVE_LAYER + LOCAL_INTEG004 + GITHUB + VT) ===
# H01 AgentSession excluded from Ext product link — FIVE_LAYER CONFIRMED
Set-Row 'H01' 'CONFIRMED' 'H01;PR78;ISSUE49;AgentSession;FIVE_LAYER' $CC79 `
  "$lane\FIVE_LAYER_SOURCE_AUDIT_001.md;CMakeLists.txt:4084-4111 vs :5547-5554" `
  'Link rawrxd_agentic_backend into RawrXD-Win32IDE-Native-Ext product path; then AgentSession E2E on same SHA'

# H02 debugger IDC split 1313+ vs 2100+ — FIVE_LAYER CONFIRMED
Set-Row 'H02' 'CONFIRMED' 'H02;G-IDE-DEBUG-UI;I57-A14;FIVE_LAYER' $CC79 `
  "$lane\FIVE_LAYER_SOURCE_AUDIT_001.md;Win32IDE.cpp:1435-1453;Win32IDE_Debugger.cpp:21-36" `
  'Unify debugger control ID namespace; remeasure IDE Debug UI SESSION_REAL'

# H13 menu ID drift / 3014 cross-tree — FIVE_LAYER CONFIRMED
Set-Row 'H13' 'CONFIRMED' 'H13;H10;PR77;FIVE_LAYER' $CC79 `
  "$lane\FIVE_LAYER_SOURCE_AUDIT_001.md;Win32IDE_CommandIDs.h:51;PR77_ACCEPTANCE_001\RECEIPT.md" `
  'Freeze single command-ID SSOT before four-panel/harness binds 3014'

# CONFIRMED: VS_UNICODE_OUTPUT on CC79 (historical root cause; IDE feed still open on controlling tip)
Set-Row 'H27' 'CONFIRMED' 'H27;PROBLEMS_PANEL_GATE;COMPILER_ROOT_CAUSE_001;I57-overlap;PR75/PR77' $CC79 `
  "$lane\PROBLEMS_PANEL_GATE.md;$lane\artifacts\COMPILER_ROOT_CAUSE_001.txt;$lane\artifacts\COMPILER_CAPTURE_ISOLATED_RECEIPT.txt" `
  'CC79 PROBLEMS still items=0. Candidate tip_004 live 35EFA9BA measured items=3 — NO_CROSS_SHA inherit; remeasure controlling/single-SHA'

Set-Row 'H28' 'CONFIRMED' 'H28;H27;G-PROBLEMS;FIVE_LAYER' $CC79 `
  "$lane\FIVE_LAYER_SOURCE_AUDIT_001.md;$lane\artifacts\COMPILER_ROOT_CAUSE_001.txt" `
  'Historical pipe/drain axis CONFIRMED with C1; product EXE remeasure beyond candidate feed still required on single SHA'

# PROBLEMS empty list on CC79 — product gate row (controlling)
Add-Row 'G-PROBLEMS' 'Problems panel items=0 / click-to-line not measured on CC79 controlling tip' 'CONFIRMED' `
  'G-PROBLEMS;H27;H28;H32;H34-H36;PR77;I57-A11;F25' $CC79 `
  "$lane\PROBLEMS_PANEL_GATE.md;$lane\MASTER_STATUS_CC79.md;$lane\FINAL_VERDICT.md;$lane\LOCAL_INTEG004_FINISH25_LOCATOR.md" `
  'Single-SHA: PROBLEMS_ITEMS>0 + click-to-line on same SHA as EXT/CHAT/TERM/OUTPUT. tip_004 live feed ≠ CC79 PASS'

Add-Row 'G-IDE-DEBUG-UI' 'IDE Debug Console UI E2E FAIL (headless PASS ≠ UI PASS)' 'CONFIRMED' `
  'G-IDE-DEBUG-UI;H02;F25-T21-T23;I57-A14;PR77' $CC79 `
  "$lane\DEBUG_CONSOLE_GATE.md;$lane\FINAL_VERDICT.md;$lane\FIVE_LAYER_SOURCE_AUDIT_001.md" `
  'Live BP/step/continue/stop UI with SESSION_REAL; resolve H02 IDC split first'

Add-Row 'G-FOUR-PANEL' 'Four-panel integration OPEN (Problems+Debug UI blockers)' 'CONFIRMED' `
  'G-FOUR-PANEL;H118;PR77;FOLLOWUP_CC79_FOUR_PANEL' $CC79 `
  "$lane\FOUR_PANEL_INTEGRATION.md;$lane\FOLLOWUP_CC79_FOUR_PANEL.md" `
  'After Problems feed + IDE Debug UI close on one SHA; then four-panel scenarios'

Add-Row 'G-VT-CONSOLE' 'Console VT/CSI literal FAIL in RichEdit PowerShell panel vs ConPTY -NoExit' 'CONFIRMED' `
  'G-VT-CONSOLE;G-TERM;PR77;CONSOLE_RENDER_CSI' $CC79 `
  "$lane\CONSOLE_RENDER_CSI_LITERAL_FAIL.md" `
  'Capture RUNNING_EXE_SHA then strip/VT-interpret or noninteractive pump; do not invent COMMAND_EXECUTION PASS'

Add-Row 'G-RECEIPT-CLOBBER' 'Sealed receipt path durability FAIL (OUTPUT/EXT receipt filenames overwritten)' 'CONFIRMED' `
  'G-RECEIPT-CLOBBER;G-OUTPUT;G-EXT;FIVE_LAYER' $CC79 `
  "$lane\FIVE_LAYER_SOURCE_AUDIT_001.md;artifacts\CC79_FOUR_PANEL_DEBUG_UI_RECEIPT.txt;ext_runtime_receipt.txt" `
  'Prefer timed runlogs as authority; stop single-path clobber of sealed filenames'

# SEALED_PASS on CC79 only
Add-Row 'G-EXT' 'ExtensionHost smoke PASS (sealed on CC79)' 'SEALED_PASS' `
  'G-EXT;F25-T16;PR79;H43-H56' $CC79 `
  "$lane\MASTER_STATUS_CC79.md;$lane\FINAL_VERDICT.md" `
  'Preserve; re-prove on any tip move. INTEG_004 EXT_CLEANUP=FAIL is separate SHA'

Add-Row 'G-CHAT' 'Chat Ctrl+Enter send 7/7 PASS (sealed on CC79)' 'SEALED_PASS' `
  'G-CHAT;F25-T20;Issue49-IDE_CHAT' $CC79 `
  "$lane\MASTER_STATUS_CC79.md;$lane\FINAL_VERDICT.md" `
  'Preserve; no cross-SHA inherit'

Add-Row 'G-TERM' 'Terminal PASS (sealed on CC79)' 'SEALED_PASS' `
  'G-TERM;F25-T17;I57-A09;PR77' $CC79 `
  "$lane\MASTER_STATUS_CC79.md;artifacts\term_smoke_receipt_CC79.txt" `
  'Preserve; ConPTY product-path still tracked under PR77 acceptance'

Add-Row 'G-OUTPUT' 'Output GUI PASS (sealed on CC79)' 'SEALED_PASS' `
  'G-OUTPUT;PR77;FOUR_PANEL' $CC79 `
  "$lane\FINAL_VERDICT.md;$lane\MASTER_STATUS_CC79.md" `
  'Preserve; four-panel still OPEN'

Add-Row 'G-DEBUG-HEADLESS' 'Debug backend headless PASS (sealed on CC79)' 'SEALED_PASS' `
  'G-DEBUG-HEADLESS;DEBUG_CONSOLE_GATE' $CC79 `
  "$lane\DEBUG_CONSOLE_GATE.md;artifacts\debug_backend_verify_CC79_receipt.txt" `
  'Does NOT credit IDE_DEBUG_UI; UI remains FAIL'

# F25 CURRENT sealed on CC79
Add-Row 'F25-T10' 'Finish25 T10 session recovery CURRENT PASS on CC79 freeze lineage' 'SEALED_PASS' `
  'F25-T10;H26;H69' $CC79 "$lane\FINISH25_MATRIX.md" 'Historical authority separate; CURRENT=PASS this tip'
Add-Row 'F25-T16' 'Finish25 T16 EXT CURRENT PASS on CC79' 'SEALED_PASS' `
  'F25-T16;G-EXT' $CC79 "$lane\FINISH25_MATRIX.md" 'Preserve'
Add-Row 'F25-T17' 'Finish25 T17 Terminal CURRENT PASS on CC79' 'SEALED_PASS' `
  'F25-T17;G-TERM' $CC79 "$lane\FINISH25_MATRIX.md" 'Preserve'
Add-Row 'F25-T20' 'Finish25 T20 Chat CURRENT PASS on CC79' 'SEALED_PASS' `
  'F25-T20;G-CHAT' $CC79 "$lane\FINISH25_MATRIX.md" 'Preserve'

# F25 historical remaining — UNVERIFIED on controlling tip (do not invent FAIL from old SHA as current CONFIRMED without CC79 measure)
Add-Row 'F25-T05' 'Finish25 T05 cancel/recovery CURRENT' 'UNVERIFIED' 'F25-T05;H58;H75' $CC79 "$lane\FINISH25_MATRIX.md;POST_E59D FINISH_25_BACKLOG" 'Measure cancel Request-A on CC79/candidate'
Add-Row 'F25-T07' 'Finish25 T07 unicode/binary open CURRENT' 'UNVERIFIED' 'F25-T07' $CC79 "$lane\FINISH25_MATRIX.md" 'Retest on controlling SHA'
Add-Row 'F25-T08' 'Finish25 T08 multi-tab CURRENT (TIP_FIX=0 sealed causality unproven)' 'UNVERIFIED' 'F25-T08' $CC79 "$lane\FINISH25_MATRIX.md" 'TIP_FIX=0; do not invent PASS'
Add-Row 'F25-T18' 'Finish25 T18 soak CURRENT' 'UNVERIFIED' 'F25-T18;H101' $CC79 "$lane\FINISH25_MATRIX.md" 'NOT_RUN on CC79'
Add-Row 'F25-T19' 'Finish25 T19 memory/handles CURRENT' 'UNVERIFIED' 'F25-T19;H76' $CC79 "$lane\FINISH25_MATRIX.md" 'NOT_RUN on CC79'
Add-Row 'F25-T24' 'Finish25 T24 packaging CURRENT PARTIAL_STAGE_ONLY' 'UNVERIFIED' 'F25-T24;H98-H100;I57-C15' $CC79 "$lane\FINISH25_MATRIX.md" 'Installer/rollback E2E'
Add-Row 'F25-T25' 'Finish25 T25 CERTIFIED/PROMOTE conjunction' 'UNVERIFIED' 'F25-T25;H106;Issue49' $CC79 "$lane\FINISH25_MATRIX.md" 'CERTIFIED=0 PROMOTE=0 held'

# INTEG_004 / tip_004 candidate-specific (not controlling; must NOT supersede CC79)
Add-Row 'INTEG004-PROBLEMS' 'INTEG_004 sealed Problems UI items=3 + click-to-line (candidate SHA 47451F24 only; EXE ABSENT)' 'UNVERIFIED' `
  'INTEG004-PROBLEMS;H27;H36;G-PROBLEMS' $INTEG `
  "$lane\INTEG004_ACCEPTANCE_DISPOSITION.md;$lane\LINEAGE_RECONCILE_EA5D_CC79_INTEG004.md;$lane\LOCAL_INTEG004_FINISH25_LOCATOR.md" `
  'NO_CROSS_SHA_INHERIT. Sealed receipt only; live tip_004 EXE churned away from 47451F24'

Add-Row 'TIP004-IDE-FEED-LIVE' 'tip_final_integ_004 live IDE compiler feed PROBLEMS_ITEMS=3 (candidate 35EFA9BA; NOT controlling)' 'UNVERIFIED' `
  'TIP004-IDE-FEED-LIVE;G-PROBLEMS;H27;LOCAL_INTEG004' $TIP004_LIVE `
  "$lane\artifacts\IDE_COMPILER_FEED_RECEIPT.txt;$lane\candidates\tip_final_integ_004\SHA256.txt;$lane\LOCAL_INTEG004_FINISH25_LOCATOR.md" `
  'CANDIDATE_NOT_PROMOTED=1. Does not clear G-PROBLEMS on CC79. Prior live 69FE3D92 measured items=0 (locator). tip_003/004 MUST NOT SUPERSEDE CC79'

Add-Row 'INTEG004-EXT-CLEANUP' 'INTEG_004 ExtensionHost --ext-quit FORCE_KILL / EXT_CLEANUP=FAIL' 'CONFIRMED' `
  'INTEG004-EXT-CLEANUP;H51;PR79;G-EXT' $INTEG `
  "$lane\INTEG004_EXT_REVERIFY_RECEIPT.md;$lane\LOCAL_INTEG004_FINISH25_LOCATOR.md" `
  'Fix clean quit without FORCE_KILL; reverify on measured tip_004 SHA (live≠sealed)'

Add-Row 'INTEG004-VSUNICODE-FIX' 'VS_UNICODE_OUTPUT scrub + FORCE_PIPE SOURCE_WIRED; IDE feed RUNTIME on candidate only' 'UNVERIFIED' `
  'INTEG004-VSUNICODE-FIX;H27;H28;COMPILER_CAPTURE;FIVE_LAYER' $TIP004_LIVE `
  "$lane\artifacts\COMPILER_CAPTURE_ISOLATED_RECEIPT.txt;$lane\artifacts\IDE_COMPILER_FEED_RECEIPT.txt;$lane\FIVE_LAYER_SOURCE_AUDIT_001.md" `
  'SOURCE_WIRED≠RUNTIME_REACHED on CC79; FORCE_PIPE scrub ≠ IDE feed seal on controlling tip'

# Issue #49 milestone
Add-Row 'ISSUE49' 'Product-Final single-SHA autonomous coding loop (Issue #49)' 'UNVERIFIED' `
  'ISSUE49;H120;F25-T25;Layer10' $CC79 `
  'gh:ItsMehRAWRXD/RawrXD#49' `
  'Execute clean-clone→model→GPU→agent edit/build-fail/repair/test/review/commit on ONE SHA. ISSUE49_MILESTONE=NOT_DEMONSTRATED'

# Issue #57 gates (45) — OUT_OF_SCOPE for multi-platform
$A = @(
'Resolve GHA runner_id=0 empty steps; successful Linux+Windows run',
'Re-run source-only per-file SHA-256 inventory; archive JSON',
'Re-run CMake literal-source admission; disposition missing paths',
'Strict no-external-dependencies scan; quarantine Qt/nlohmann prod links',
'Frozen manifest feature→TU→call site',
'Rebuild real native Win32 IDE clean checkout no-Qt',
'Rebuild rawr.exe and snapshot/agent targets same checkout',
'Launch Win32 IDE save/close/reopen compare file SHA-256',
'Verify terminal start/output/exit/cancel/cleanup',
'Verify native PowerShell panel lifecycle',
'Verify native LSP JSON-RPC handshake/diagnostics/defs/completion',
'Verify GhostText display/accept/cancel real model adapter',
'Verify native browser rendering/origin isolation/lifecycle',
'Verify debugger BP/step/watch/vars in real debuggee',
'Prove IDE agent edit→build→test→snapshot rollback with evidence'
)
for ($i=0;$i -lt 15;$i++) {
  $n = '{0:D2}' -f ($i+1)
  $st = 'UNVERIFIED'
  $maps = "I57-A$n"
  # overlap notes
  if ($i -eq 8) { $maps += ';G-TERM;F25-T17' }
  if ($i -eq 10) { $maps += ';H107' }
  if ($i -eq 11) { $maps += ';H108' }
  if ($i -eq 12) { $maps += ';H109' }
  if ($i -eq 13) { $maps += ';G-IDE-DEBUG-UI;H36' }
  if ($i -eq 14) { $maps += ';ISSUE49;H120' }
  if ($i -eq 0) { $maps += ';H103'; $st='UNVERIFIED' } # empty CI runners = infrastructure NOT_RUN ≠ invent CONFIRMED product defect
  if ($i -eq 8) { $st = 'SEALED_PASS' } # A09 terminal PASS on CC79 only
  Add-Row "I57-A$n" $A[$i] $st $maps $CC79 "$lane\GITHUB_ACCEPTANCE_RECONCILE_001.md;gh:ItsMehRAWRXD/RawrXD#57" 'Revision-specific runtime receipt required; CC79 A09 ≠ product-final'
}

$B = @(
'Recover slingshot braid format owners with hashes',
'SBraid emitter/read-back roundtrip + corrupt rejection',
'Review SlingshotGuard concurrency before Deep2 integration',
'Replace SlingshotPOC simulated VRAM with real allocator if promoted',
'Reconcile legacy slingshot vs Deep2 residency/loader',
'Recover compiler/linker source inventory MASM/native',
'Prove native C frontend compiles representative programs',
'Prove native C++20 frontend templates/exceptions/ABI',
'Prove MASM x86/x64 COFF interoperability with oracle',
'Prove NASM x86/x64 object interoperability with oracle',
'Prove rawrxd native linker PE32/PE32+ startup/imports/reloc/exports',
'Prove compile→link→execute without external compiler for subsets',
'Define ELF/Linux capability vs host-toolchain fallback + smoke',
'Define Mach-O/macOS/iOS contracts with macOS runner evidence',
'Define Android ABI/ELF/APK contracts with device evidence'
)
for ($i=0;$i -lt 15;$i++) {
  $n = '{0:D2}' -f ($i+1)
  $st = 'UNVERIFIED'
  $maps = "I57-B$n;PR75"
  if ($i -ge 12) { $st = 'OUT_OF_SCOPE'; $maps += ';H114' } # ELF/Mach-O/Android
  if ($i -eq 9) { $st = 'OUT_OF_SCOPE'; $maps += ';NASM_ALT_ASSEMBLER' } # B10 NASM OOS for Win daily-driver
  if ($i -eq 10 -or $i -eq 11) { $maps += ';H41;H42' }
  Add-Row "I57-B$n" $B[$i] $st $maps $CC79 "$lane\GITHUB_ACCEPTANCE_RECONCILE_001.md;gh:ItsMehRAWRXD/RawrXD#57" $(if($st -eq 'OUT_OF_SCOPE'){'Outside approved Windows daily-driver 100% spec unless product spec expands'}else{'Runtime receipt on Windows PE path'})
}

$C = @(
'Deterministic reference model/quant baseline receipts',
'Verify ffn_gate_up multi-token GPU path before perf promote',
'Verify Deep2 Q4_K/Q5_K/Q6_K/F32 fused GEMV vs oracles',
'Compare four fused GEMV paths submit/fence wait counts',
'Lane-state restoration success/error/fallback/dual-GPU',
'Measure R9700 single-GPU TPS 32/128/256 with paired control',
'Measure RX7800 XT single-GPU TPS 32/128/256 with paired control',
'Measure dual-GPU full-model TPS both devices no-fallback',
'Attribute GPU0 fence waits and GPU1 overlap timestamps',
'Certify GGUF shard/index/quant/arch on supported matrix',
'Nemotron SSM Q4_K NaN/residual parity',
'Benchmark real-model 150+ single-stream decode TPS if attainable',
'Identical model/sampling/seed/context/clocks for perf A/B',
'Apply 25 IDE ×20 capability = 500-cell matrix with real evidence',
'Certify signed/reproducible packaging/security/crash/rollback/offline/release'
)
for ($i=0;$i -lt 15;$i++) {
  $n = '{0:D2}' -f ($i+1)
  $maps = "I57-C$n"
  if ($i -ge 5 -and $i -le 8) { $maps += ';H78;H82;H83;H88' }
  if ($i -eq 10) { $maps += ';H79' }
  if ($i -eq 13) { $maps += ';F25;H117' }
  if ($i -eq 14) { $maps += ';F25-T24;H98-H106' }
  Add-Row "I57-C$n" $C[$i] 'UNVERIFIED' $maps $CC79 'gh:ItsMehRAWRXD/RawrXD#57' 'Measured GPU/runtime receipt; no synthetic TPS'
}

# PRs
Add-Row 'PR75' 'Native compiler/CMake/PE-COFF linker pipeline (37 local adapter PASS; 16 linker tests unexecuted; CI runner empty)' 'UNVERIFIED' `
  'PR75;H41;H42;I57-B;H103' '3bbda91366161c08c103cd1111dc413e92bdd25b' 'gh:ItsMehRAWRXD/RawrXD#75' 'Execute native linker tests + Windows PE runtime; CI runner assignment'
Add-Row 'PR76' 'Deep2 + native compiler consolidation into main (draft; CI BlobNotFound; conflicts)' 'UNVERIFIED' `
  'PR76;H10;H104' 'e91b476b51902e26fd1b0c3678ffce84efe7057d' 'gh:ItsMehRAWRXD/RawrXD#76' 'Reconcile divergence/conflicts; CI before merge auth'
Add-Row 'PR77' 'IDE product path ConPTY/inference UI/Problems/output (OPEN; MERGE_AUTHORIZED=0)' 'UNVERIFIED' `
  'PR77;G-PROBLEMS;G-FOUR-PANEL;G-TERM' '9edf63fed82bdf427f734591bff262282f6fe822' 'gh:ItsMehRAWRXD/RawrXD#77' 'SHA-specific four-panel evidence; no inherit'
Add-Row 'PR78' 'AgentSession GUI lifecycle/cancel/cleanup (OPEN)' 'UNVERIFIED' `
  'PR78;H57-H72' '84b4725f798f329a31660e87820c2f57115247ce' 'gh:ItsMehRAWRXD/RawrXD#78' 'Session start/stop/kill/restore proof on branch EXE'
Add-Row 'PR79' 'ExtensionHost runtime host/worker IPC/shutdown/crash recovery (OPEN)' 'UNVERIFIED' `
  'PR79;H43-H56;INTEG004-EXT-CLEANUP' '13c33a6f35c6493cd5bf60a9f5f0a21f6271ef8c' 'gh:ItsMehRAWRXD/RawrXD#79' 'Real extension load/execute + clean shutdown evidence'

# H08 related to VS_UNICODE — already covered by H27 CONFIRMED; mark H08 UNVERIFIED with maps (env vars broader)
Set-Row 'H08' 'UNVERIFIED' 'H08;H27' $CC79 "$lane\artifacts\COMPILER_ROOT_CAUSE_001.txt" 'Broader env-poison audit beyond VS_UNICODE_OUTPUT'

# H32 unicode diagnostics — CONFIRMED axis with C1/H27 on CC79
Set-Row 'H32' 'CONFIRMED' 'H32;H27;G-PROBLEMS;DUPLICATE_OF:C1' $CC79 "$lane\PROBLEMS_PANEL_GATE.md;$lane\HIDDEN_GAP_AUDIT_001\MASTER_DEFECT_REGISTER.md" 'Same axis as G-PROBLEMS/H27; do not double-count'

# H36 click-to-line: UNVERIFIED on CC79 (NOT_RUN); INTEG_004 sealed has PASS; tip_004 live feed items=3 click-to-line not re-sealed here
Set-Row 'H36' 'UNVERIFIED' 'H36;G-PROBLEMS;INTEG004-PROBLEMS;TIP004-IDE-FEED-LIVE' $CC79 "$lane\PROBLEMS_PANEL_GATE.md;$lane\artifacts\IDE_COMPILER_FEED_RECEIPT.txt" 'CLICK_TO_LINE=NOT_RUN on CC79; candidate feed ≠ controlling'

# H51 confirmed on integ004 cleanup path — keep CONFIRMED only if evidence on a SHA; integ004 is CONFIRMED for cleanup
Set-Row 'H51' 'CONFIRMED' 'H51;INTEG004-EXT-CLEANUP;PR79' $INTEG "$lane\INTEG004_EXT_REVERIFY_RECEIPT.md" 'Clean --ext-quit without FORCE_KILL on candidate; re-check CC79 separately'

# H103 CI runner — UNVERIFIED (empty runners = NOT_RUN; do not invent CONFIRMED product defect)
Set-Row 'H103' 'UNVERIFIED' 'H103;I57-A01;PR75;PR76' 'n/a-ci' "$lane\GITHUB_ACCEPTANCE_RECONCILE_001.md;gh:#57;#75;#76" 'Capture successful Linux+Windows Actions run with steps>0; NOT_RUN≠PASS≠CONFIRMED_DEFECT'

# H106 multi-SHA cert risk — UNVERIFIED (policy risk; lineage docs warn)
Set-Row 'H106' 'UNVERIFIED' 'H106;ISSUE49;F25-T25' $CC79 "$lane\LINEAGE_RECONCILE_EA5D_CC79_INTEG004.md" 'Single-SHA product-final only'

# H114 / H120
Set-Row 'H114' 'OUT_OF_SCOPE' 'H114;I57-B13-B15' $CC79 'Issue57 B13-B15 + product scope law' 'OUT_OF_SCOPE unless approved Windows daily-driver spec expands'
Set-Row 'H120' 'UNVERIFIED' 'H120;ISSUE49' $CC79 'gh:#49' 'ISSUE49_MILESTONE=NOT_DEMONSTRATED'

# H118 four-panel simultaneity — maps to CONFIRMED four-panel open
Set-Row 'H118' 'CONFIRMED' 'H118;G-FOUR-PANEL' $CC79 "$lane\FOUR_PANEL_INTEGRATION.md" 'Integrated four-panel scenarios on one SHA'

# D001 debugger stub from DEFECT_REGISTER — UNVERIFIED as "stub" claim vs CC79 headless PASS; don't invent CONFIRMED stub if headless works — mark INVESTIGATE maps
Add-Row 'D001' 'Historical DEFECT_REGISTER debugger UI simulation claim' 'INVESTIGATE' `
  'D001;G-IDE-DEBUG-UI;G-DEBUG-HEADLESS' $CC79 'RAWRXD_FULL_IDE_AUDIT_003\DEFECT_REGISTER.csv' 'Reconcile stub claim vs CC79 headless PASS + UI FAIL'

# A4F immutable note row
Add-Row 'A4F-IMMUTABLE' 'Frozen slim daily-driver baseline A4F must not be overwritten' 'SEALED_PASS' `
  'A4F;DAILY_DRIVER_CLOSE_001' $A4F 'DAILY_DRIVER_CLOSE_001\IMMUTABLE_SLIM_BASELINE_A4F083DF.md' 'Keep immutable; not product-final milestone'

# Prior ~78 reconstruction meta (not a defect)
# Finish25(25)+Issue57(45)+CC79 board(~8 seals/opens) ≈78 named acceptance items in prior inventory narrative

# Counts
$by = $rows | Group-Object Status | Sort-Object Name
$counts = @{}
foreach ($g in $by) { $counts[$g.Name] = $g.Count }

# Dedupe stats
$dedupe = @"
DEDUPE_STATS
  ABSORBED_WORKERS=
    LOCAL_INTEG004_FINISH25_LOCATOR.md
    GITHUB_ACCEPTANCE_RECONCILE_001.md
    FIVE_LAYER_SOURCE_AUDIT_001.md (CONFIRMED=8 INVESTIGATE=14 UNVERIFIED=5 findings)
    HIDDEN_GAP_AUDIT_001\MASTER_DEFECT_REGISTER.md + REQUIREMENT_DEDUPE_MATRIX.md
    HIDDEN_GAP_AUDIT_001\MASTER_HIDDEN_GAP_REGISTER.md (d3bda9f6 skeleton PENDING_WORKER — merged, not discarded)
    CONSOLE_RENDER_CSI_LITERAL_FAIL.md (TERMINAL_VT_RENDER_FAIL_001 alias landed as this name)
    artifacts\IDE_COMPILER_FEED_RECEIPT.txt (tip_004 live 35EFA9BA)
  INPUT_H120=120 (investigation targets; not 120 confirmed defects)
  INPUT_PRIOR_78=ABSENT_LOCALLY_AS_NAMED_FILE (reconstructed narrative only; DOUBLE_COUNT=0)
  INPUT_ISSUE57=45 (GITHUB_ACCEPTANCE_RECONCILE FETCHED)
  INPUT_ISSUE49=1 milestone NOT_DEMONSTRATED
  INPUT_ISSUE50=11 layers OPEN/PARTIAL
  INPUT_PR75_79=5 OPEN (MERGE_AUTHORIZED=0)
  FINISH25_CURRENT=4/25 HISTORICAL=19/25
  FIVE_LAYER_INTERSECT=H01,H02,H13,H27,H28,G-RECEIPT-CLOBBER absorbed as CONFIRMED where cited
  RETAINED_ROWS=$($rows.Count)
  ARITHMETIC_SUM_FORBIDDEN=1
  OVERLAP_POLICY=MapsTo aliases; status from strongest local evidence; tip_003/004 NEVER supersede CC79
  OUT_OF_SCOPE_MULTI_PLATFORM=I57-B13,I57-B14,I57-B15,H114 (+ I57-B10 NASM daily-driver OOS)
"@

$blockers = @"
TOP_EVIDENCE_BACKED_BLOCKERS (Issue #49 single-SHA milestone order; PROMOTE=0)
  1. G-PROBLEMS / IDE compiler feed — PROBLEMS_ITEMS=0 on CONTROLLING CC79 (CONFIRMED). Candidate tip_004 live 35EFA9BA measured items=3 (IDE_COMPILER_FEED_RECEIPT) ≠ inherit. Prior 69FE3D92 items=0; sealed 47451F24 Problems PASS EXE ABSENT.
  2. G-VT-CONSOLE — CONSOLE_RENDERING=FAIL RichEdit CSI literals vs ConPTY powershell -NoExit (CONFIRMED) — CONSOLE_RENDER_CSI_LITERAL_FAIL.md; RUNNING_EXE_SHA NOT_CAPTURED.
  3. H01 AgentSession — implemented lib NOT linked into RawrXD-Win32IDE-Native-Ext (CONFIRMED) — FIVE_LAYER_SOURCE_AUDIT_001.md; blocks PR78/#49 agent keys.
  4. G-IDE-DEBUG-UI / H02 — IDE Debug UI FAIL + debugger IDC 1313+/2100+ split (CONFIRMED) — DEBUG_CONSOLE_GATE.md; FIVE_LAYER.
  5. G-FOUR-PANEL / H118 — four-panel OPEN until blockers 1+4 close on one SHA (CONFIRMED) — FOUR_PANEL_INTEGRATION.md.
  RELATED (not displacing top-5 order): INTEG004-EXT-CLEANUP/H51 FORCE_KILL on 47451F24; ISSUE49/H120 NOT_DEMONSTRATED; G-RECEIPT-CLOBBER; H13 menu ID drift.
"@

$cert = @"
CERT_LADDER_STATUS (Issue #50 via GITHUB_ACCEPTANCE_RECONCILE_001; layers 0–10)
  L0  PARTIAL  — provider isolated 32/32 cited; integration seal pending (#39)
  L1  OPEN     — Deep2 integration & runtime closure BLOCKED (#40)
  L2  OPEN     — PENDING (#41) GPU/Runtime
  L3  OPEN     — PENDING (#42) Agent Reasoning + Tool Authority
  L4  OPEN     — PENDING (#43) Autonomous Edit/Build/Test
  L5  OPEN     — PENDING (#44) Multi-Agent / Dual-GPU
  L6  PARTIAL  — PENDING (#45); CC79 IDE CHAT/TERM/OUTPUT/EXT seals ≠ Layer-6 seal
  L7  OPEN     — PENDING (#46) Repo/CMake
  L8  OPEN     — PENDING (#47) CI/Release
  L9  OPEN     — PENDING (#48) Performance (blocks #49)
  L10 OPEN     — (#49) ISSUE49_MILESTONE=NOT_DEMONSTRATED
  NOTE: No layer marked PASS — isolated provider tests ≠ L0 integration seal PASS
"@

$nextActions = @"
NEXT_ACTIONS (max 5; prioritized for Issue #49 single-SHA path)
  1. IDE compiler feed → PROBLEMS_ITEMS>0 on measured product SHA with click-to-line; close G-PROBLEMS on controlling/single-SHA (candidate 35EFA9BA feed ≠ CC79; no tip climb).
  2. VT/RichEdit console render FAIL vs ConPTY -NoExit — capture RUNNING_EXE_SHA then strip/interpret/noninteractive pump (CONSOLE_RENDER_CSI_LITERAL_FAIL.md).
  3. AgentSession link into Ext product path (H01 / PR78) — CMake link rawrxd_agentic_backend into Native-Ext; then lifecycle E2E.
  4. IDE debug UI E2E — resolve H02 IDC split; SESSION_REAL via IDE UI (headless PASS ≠ UI PASS).
  5. Four-panel integration AFTER 1+4 on the same SHA (G-FOUR-PANEL / H118).
"@

# Build markdown
$sb = New-Object System.Text.StringBuilder
[void]$sb.AppendLine('# MASTER_HIDDEN_GAP_REGISTER_001')
[void]$sb.AppendLine('')
[void]$sb.AppendLine("ASOF_UTC=$asof")
[void]$sb.AppendLine('MOTD_ACK=1')
[void]$sb.AppendLine('CONTROLLING_TIP=CC79')
[void]$sb.AppendLine("CONTROLLING_TIP_SHA256=$CC79")
[void]$sb.AppendLine('TIP_LABEL=tip_final_integ_002')
[void]$sb.AppendLine("FROZEN_A4F=$A4F")
[void]$sb.AppendLine('A4F_IMMUTABLE=1')
[void]$sb.AppendLine('PROMOTE=0')
[void]$sb.AppendLine('CERTIFIED=0')
[void]$sb.AppendLine('PRODUCT_PASS=0')
[void]$sb.AppendLine('INVENT_PASS=0')
[void]$sb.AppendLine('INVENT_CONFIRMED_DEFECT=0')
[void]$sb.AppendLine('ENGINEERING_MATURITY_ESTIMATE=82%')
[void]$sb.AppendLine('ESTIMATE_CHANGE=0')
[void]$sb.AppendLine('ISSUE49_MILESTONE=NOT_DEMONSTRATED')
[void]$sb.AppendLine('MAJOR_INTEGRATED_ACCEPTANCE=NOT_DEMONSTRATED')
[void]$sb.AppendLine('NO_CROSS_SHA_PASS_INHERITANCE=1')
[void]$sb.AppendLine('NO_IDE_REBUILD_THIS_DELIVERABLE=1')
[void]$sb.AppendLine('')
[void]$sb.AppendLine('## Law')
[void]$sb.AppendLine('')
[void]$sb.AppendLine('```')
[void]$sb.AppendLine('SOURCE_WIRED != RUNTIME_REACHED != TOKEN_SURVIVED != PERFORMANCE_PASS')
[void]$sb.AppendLine('NOT_RUN != PASS')
[void]$sb.AppendLine('H_INVESTIGATE != CONFIRMED_DEFECT')
[void]$sb.AppendLine('SEALED_PASS requires exact SHA evidence on cited tip (CC79 for controlling)')
[void]$sb.AppendLine('INTEG_004 / tip_003 / tip_004 MUST NOT SUPERSEDE CC79')
[void]$sb.AppendLine('tip_final_integ_003 SHA (DD60FFB8 / hist 0EA05DF7) != CONTROLLING')
[void]$sb.AppendLine('tip_final_integ_004 SHA (live 35EFA9BA / prior live 69FE3D92 / sealed 47451F24) != CONTROLLING')
[void]$sb.AppendLine('CROSS_SHA_PASS_INHERITANCE=0')
[void]$sb.AppendLine('A4F_IMMUTABLE=1')
[void]$sb.AppendLine('ENGINEERING_MATURITY_ESTIMATE=82% ESTIMATE_CHANGE=0')
[void]$sb.AppendLine('ISSUE49_MILESTONE=NOT_DEMONSTRATED')
[void]$sb.AppendLine('```')
[void]$sb.AppendLine('')
[void]$sb.AppendLine('## Status vocabulary')
[void]$sb.AppendLine('')
[void]$sb.AppendLine('- CONFIRMED — local/gh evidence of failure or open measured gate')
[void]$sb.AppendLine('- UNVERIFIED — required behavior not demonstrated on cited SHA')
[void]$sb.AppendLine('- INVESTIGATE — plausible mechanism; not assumed present')
[void]$sb.AppendLine('- SEALED_PASS — exact SHA receipt on cited tip')
[void]$sb.AppendLine('- OUT_OF_SCOPE — outside approved Windows daily-driver product spec')
[void]$sb.AppendLine('')
[void]$sb.AppendLine('## SHA lineage (tip_003/004 must NOT supersede CC79)')
[void]$sb.AppendLine('')
[void]$sb.AppendLine('| Role | Tip / label | SHA-256 | Notes |')
[void]$sb.AppendLine('|------|-------------|---------|-------|')
[void]$sb.AppendLine("| **CONTROLLING** | tip_final_integ_002 | ``$CC79`` | LIVE MATCH; SIZE authority; PROMOTE=0 |")
[void]$sb.AppendLine("| Frozen baseline | A4F slim | ``$A4F`` | **UNTOUCHED / IMMUTABLE** |")
[void]$sb.AppendLine("| CANDIDATE hist | tip_final_integ_003 | ``$TIP003_HIST`` | Receipt-only; EXE ABSENT |")
[void]$sb.AppendLine("| CANDIDATE live | tip_final_integ_003 | ``$TIP003_LIVE`` | NOT_CONTROLLING |")
[void]$sb.AppendLine("| CANDIDATE sealed Problems/EXT | tip_final_integ_004 / INTEG_004 | ``$INTEG`` | Problems PASS + EXT_CLEANUP FAIL receipts; EXE ABSENT |")
[void]$sb.AppendLine("| CANDIDATE prior live | tip_final_integ_004 | ``$TIP004_PRIOR`` | Locator-era; PROBLEMS=0 measure |")
[void]$sb.AppendLine("| CANDIDATE live now | tip_final_integ_004 | ``$TIP004_LIVE`` | IDE_COMPILER_FEED items=3; CANDIDATE_NOT_PROMOTED; **≠ CC79** |")
[void]$sb.AppendLine('')
[void]$sb.AppendLine('```')
[void]$sb.AppendLine('TIP_003_004_MUST_NOT_SUPERSEDE_CC79=1')
[void]$sb.AppendLine('TIP_MOVE_AUTHORIZED=0')
[void]$sb.AppendLine('TIP_CLIMB=HOLD')
[void]$sb.AppendLine('```')
[void]$sb.AppendLine('')
[void]$sb.AppendLine('## DEDUPE_STATS')
[void]$sb.AppendLine('')
[void]$sb.AppendLine('```')
[void]$sb.AppendLine($dedupe)
[void]$sb.AppendLine('```')
[void]$sb.AppendLine('')
[void]$sb.AppendLine('## TOP_EVIDENCE_BACKED_BLOCKERS')
[void]$sb.AppendLine('')
[void]$sb.AppendLine('```')
[void]$sb.AppendLine($blockers)
[void]$sb.AppendLine('```')
[void]$sb.AppendLine('')
[void]$sb.AppendLine('## NEXT_ACTIONS')
[void]$sb.AppendLine('')
[void]$sb.AppendLine('```')
[void]$sb.AppendLine($nextActions)
[void]$sb.AppendLine('```')
[void]$sb.AppendLine('')
[void]$sb.AppendLine('## CERT_LADDER_STATUS')
[void]$sb.AppendLine('')
[void]$sb.AppendLine('```')
[void]$sb.AppendLine($cert)
[void]$sb.AppendLine('```')
[void]$sb.AppendLine('')
[void]$sb.AppendLine('## Counts by status')
[void]$sb.AppendLine('')
[void]$sb.AppendLine('```')
foreach ($k in ($counts.Keys | Sort-Object)) {
  [void]$sb.AppendLine(("  {0}={1}" -f $k, $counts[$k]))
}
[void]$sb.AppendLine(("  TOTAL_RETAINED={0}" -f $rows.Count))
[void]$sb.AppendLine('```')
[void]$sb.AppendLine('')
[void]$sb.AppendLine('## Master register')
[void]$sb.AppendLine('')
[void]$sb.AppendLine('| ID | Title | Status | MapsTo | ControllingSHA | EvidencePath | NextProof |')
[void]$sb.AppendLine('|----|-------|--------|--------|----------------|--------------|-----------|')

foreach ($r in ($rows | Sort-Object {
  # sort: G/F25/ISSUE/PR/I57/D/INTEG/A4F then H numeric
  if ($_.ID -match '^H(\d+)$') { 'H' + ([int]$Matches[1]).ToString('000') }
  else { $_.ID }
})) {
  $title = ($r.Title -replace '\|','/').Trim()
  $maps = ($r.MapsTo -replace '\|',';').Trim()
  $ev = ($r.EvidencePath -replace '\|',';').Trim()
  $np = ($r.NextProof -replace '\|',';').Trim()
  [void]$sb.AppendLine(("| {0} | {1} | {2} | {3} | `{4}` | {5} | {6} |" -f $r.ID,$title,$r.Status,$maps,$r.ControllingSHA,$ev,$np))
}

[void]$sb.AppendLine('')
[void]$sb.AppendLine('## Finish25 snapshot (authoritative local)')
[void]$sb.AppendLine('')
[void]$sb.AppendLine('```')
[void]$sb.AppendLine('FINISH25_HISTORICAL=19/25  (POST_E59D_CANDIDATE_001\FINISH_25_BACKLOG.md; remaining T05 T07 T08 T18 T19 T25)')
[void]$sb.AppendLine('FINISH25_CURRENT_ON_CC79=4/25  (T10,T16,T17,T20) — FINISH25_MATRIX.md')
[void]$sb.AppendLine('CITED=LOCAL_INTEG004_FINISH25_LOCATOR.md')
[void]$sb.AppendLine('NO_CROSS_SHA_PASS_INHERITANCE=1')
[void]$sb.AppendLine('```')
[void]$sb.AppendLine('')
[void]$sb.AppendLine('## GitHub fetch disposition')
[void]$sb.AppendLine('')
[void]$sb.AppendLine('```')
[void]$sb.AppendLine('AUTHORITY_SLICE=GITHUB_ACCEPTANCE_RECONCILE_001.md')
[void]$sb.AppendLine('ISSUE49=FETCHED OPEN; ISSUE49_MILESTONE=NOT_DEMONSTRATED; E2E=NOT_RUN')
[void]$sb.AppendLine('ISSUE50=FETCHED OPEN cert ladder 0-10; L0 PARTIAL; L1 BLOCKED; L2-10 not closed')
[void]$sb.AppendLine('ISSUE57=FETCHED OPEN 0/45 checked; A09 PASS on CC79 only; B10/B13-B15 OUT_OF_SCOPE')
[void]$sb.AppendLine('PR75=HELD_DRAFT MERGEABLE; isolated compiler ≠ IDE feed')
[void]$sb.AppendLine('PR76=HELD_DRAFT_CONFLICTING')
[void]$sb.AppendLine('PR77=OPEN_CONFLICTING MERGE_AUTHORIZED=0')
[void]$sb.AppendLine('PR78=OPEN_CONFLICTING AgentSession NOT_RUN')
[void]$sb.AppendLine('PR79=OPEN_CONFLICTING; CC79 EXT ≠ PR79 head')
[void]$sb.AppendLine('MERGED=0 MERGE_AUTHORIZED=0')
[void]$sb.AppendLine('```')
[void]$sb.AppendLine('')
[void]$sb.AppendLine('## Absorbed evidence index')
[void]$sb.AppendLine('')
[void]$sb.AppendLine('| Input | Path |')
[void]$sb.AppendLine('|-------|------|')
[void]$sb.AppendLine('| Local INTEG004 / Finish25 locator | `F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\LOCAL_INTEG004_FINISH25_LOCATOR.md` |')
[void]$sb.AppendLine('| GitHub acceptance reconcile | `F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\GITHUB_ACCEPTANCE_RECONCILE_001.md` |')
[void]$sb.AppendLine('| Five-layer source audit | `F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\FIVE_LAYER_SOURCE_AUDIT_001.md` |')
[void]$sb.AppendLine('| Prior master defect register | `F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\HIDDEN_GAP_AUDIT_001\MASTER_DEFECT_REGISTER.md` |')
[void]$sb.AppendLine('| Prior dedupe matrix | `F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\HIDDEN_GAP_AUDIT_001\REQUIREMENT_DEDUPE_MATRIX.md` |')
[void]$sb.AppendLine('| d3bda9f6 skeleton (merged) | `F:\rawrxd\evidence\HIDDEN_GAP_AUDIT_001\MASTER_HIDDEN_GAP_REGISTER.md` |')
[void]$sb.AppendLine('| VT/CSI console fail | `F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\CONSOLE_RENDER_CSI_LITERAL_FAIL.md` |')
[void]$sb.AppendLine('| IDE compiler feed receipt | `F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\artifacts\IDE_COMPILER_FEED_RECEIPT.txt` |')
[void]$sb.AppendLine('')
[void]$sb.AppendLine('## Optional matrix')
[void]$sb.AppendLine('')
[void]$sb.AppendLine("CSV: ``$csvPath``")
[void]$sb.AppendLine('')
[void]$sb.AppendLine('---')
[void]$sb.AppendLine('END_REGISTER · PROMOTE=0 · CERTIFIED=0 · ISSUE49_MILESTONE=NOT_DEMONSTRATED · MATURITY=82% · CONTROLLING_TIP=CC79 · TIP_003_004_NE_SUPERSEDE=1')

$utf8 = New-Object System.Text.UTF8Encoding $false
[System.IO.File]::WriteAllText($mdPath, $sb.ToString(), $utf8)
$rows | Export-Csv -LiteralPath $csvPath -NoTypeInformation -Encoding UTF8

Write-Output "WROTE=$mdPath"
Write-Output "CSV=$csvPath"
Write-Output ("ROWS=" + $rows.Count)
foreach ($k in ($counts.Keys | Sort-Object)) { Write-Output ("COUNT_$k=" + $counts[$k]) }
