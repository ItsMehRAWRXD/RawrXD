# Q2.5 build-recovery + authority gate — RAWRXD_EVENTLEDGER_AUTHORITY_001
#
# Two defect classes are now gated, both discovered by measurement:
#
#   CLASS A  duplicate authority: two translation units defining the same
#            fully-qualified class, where the build silently compiled both and
#            every individual compile succeeded.
#            rawrxd::continuous::EventLedger existed in BOTH EventLedger.hpp and
#            ContinuousEventLedger.hpp. The stale one had a flat global sequence
#            and a different event type; the canonical one is per-run and tagged
#            RAWRXD_CONTINUOUS_STREAM_REALITY_001.
#
#   CLASS B  compile-clean but unlinkable: a target that compiled every object
#            and then failed at link because TUs defining referenced symbols were
#            listed only in a sibling target. rawr_monolith had 20 LNK2019s.
#
# All checks here are STATIC (no build required), so they can gate a change
# before spending a compile.

$ErrorActionPreference = "Stop"
$root = "F:\~dev"
$fail = 0
function Say($k, $v) { "{0,-44} = {1}" -f $k, $v }
function Bump($n, $v) { if ($v -ne 0) { $script:fail++; "  *** $n = $v ***" } }

Write-Host "Q2.5 build-recovery + authority gate"
Write-Host "-----------------------------------------------------------------"

# --- CLASS A: duplicate fully-qualified class authorities -----------------
# Map every `class X {` / `class X final {` definition in rawrxd/src to its
# enclosing namespace, then flag any FQN defined by more than one header.
$defs = @{}
Get-ChildItem "$root\rawrxd\src" -Recurse -Include *.hpp,*.h -ErrorAction SilentlyContinue | ForEach-Object {
    $f = $_
    $ns = ""
    $lines = Get-Content $f.FullName -ErrorAction SilentlyContinue
    for ($i = 0; $i -lt $lines.Count; $i++) {
        $l = $lines[$i]
        if ($l -match '^\s*namespace\s+([A-Za-z0-9_]+)\s*\{') { $ns = $matches[1] }
        # A definition has a body or inherits; a forward declaration ends in ';'
        if ($l -match '^\s*class\s+([A-Za-z0-9_]+)\s*(final\s*)?(:|\{)' -and
            $l -notmatch '^\s*class\s+[A-Za-z0-9_]+\s*;') {
            $fqn = $(if ($ns) { "$ns::$($matches[1])" } else { $matches[1] })
            $key = $fqn
            if (-not $defs.ContainsKey($key)) { $defs[$key] = @() }
            $defs[$key] += $f.Name
        }
    }
}
$dups = @($defs.GetEnumerator() | Where-Object { ($_.Value | Sort-Object -Unique).Count -gt 1 })
Say "DUPLICATE_FQN_DEFINITIONS_SCANNED" $defs.Count
Say "DUPLICATE_FQN_DEFINITIONS_FOUND" $dups.Count
foreach ($d in $dups) {
    "    {0}  <- {1}" -f $d.Key, (($d.Value | Sort-Object -Unique) -join ", ")
}
# The EventLedger pair specifically must be gone.
$stillBoth = $dups | Where-Object { $_.Key -eq "rawrxd::continuous::EventLedger" }
Bump "EVENTLEDGER_ODR_STILL_PRESENT" $stillBoth.Count

# --- CLASS A2: the specific authority swap --------------------------------
$sd = "$root\rawrxd\src\deep2\streaming"
Say "CANONICAL_LEDGER_PRESENT"      (Test-Path "$sd\EventLedger.cpp")
Say "CANONICAL_LEDGER_HEADER_PRESENT" (Test-Path "$sd\EventLedger.hpp")
$staleLive = @("$sd\ContinuousEventLedger.cpp", "$sd\ContinuousEventLedger.hpp") |
             Where-Object { Test-Path $_ }
Say "STALE_LEDGER_IN_SOURCE_TREE"   $staleLive.Count
Bump "STALE_LEDGER_STILL_LIVE"     $staleLive.Count
Say "STALE_LEDGER_QUARANTINED"      (Test-Path "$sd\quarantine\ContinuousEventLedger.cpp.QUARANTINED")

# --- CLASS A3: forward declarations must not carry `final` ----------------
$fwdFinal = 0
Get-ChildItem "$root\rawrxd\src" -Recurse -Include *.hpp,*.h -ErrorAction SilentlyContinue | ForEach-Object {
    $m = Select-String -Path $_.FullName -Pattern '^\s*class\s+[A-Za-z0-9_]+\s+final\s*;' -ErrorAction SilentlyContinue
    if ($m) { $fwdFinal += $m.Count; "    {0}:{1}: {2}" -f $_.Name, $m[0].LineNumber, $m[0].Line.Trim() }
}
Say "FORWARD_DECL_FINAL_VIOLATIONS" $fwdFinal
Bump "FORWARD_DECL_FINAL_VIOLATIONS" $fwdFinal

# --- CLASS A4: no active build file may reference the quarantined ledger --
$active = @("$root\CMakeLists.txt", "$root\rawrxd\CMakeLists.txt",
            "$root\rawrxd\win32ide_strict\CMakeLists.txt") | Where-Object { Test-Path $_ }
$staleRefs = 0
foreach ($f in $active) {
    $lines = Get-Content $f | Where-Object { $_.Trim() -notmatch '^#' }
    $m = $lines | Select-String -Pattern "ContinuousEventLedger" -ErrorAction SilentlyContinue
    if ($m) { $staleRefs += $m.Count; "    stale: ${f}: $($m[0].Line.Trim())" }
}
Say "STALE_LEDGER_BUILD_REFS" $staleRefs
Bump "STALE_LEDGER_BUILD_REFS" $staleRefs

# --- CLASS B: every target must list the TUs its objects reference --------
# Cheap proxy: for each add_executable block, the set of listed sources must
# include every TU that defines a symbol referenced by Deep2Engine.cpp. Rather
# than a full dependency graph, assert the specific repair is present in
# BOTH targets that compile Deep2Engine.cpp.
$cm = Get-Content "$root\CMakeLists.txt"
$need = @("Beaconism.cpp","GpuScheduler.cpp","TimeReverseDigest.cpp","ModelRegistry.cpp",
          "Deep2PredictiveRouter.cpp","streaming/EventLedger.cpp",
          "DualStickStreamWindow.cpp","DualStickStreamWindow_Acquire.cpp")
$missing = @()
foreach ($n in $need) {
    # -SimpleMatch with a pre-escaped pattern would search for the literal
    # backslashes and silently match nothing, so use the plain literal form.
    $c = @($cm | Select-String -SimpleMatch -Pattern $n).Count
    if ($c -lt 2) { $missing += "$n(listed ${c}x, need >=2)" }
}
Say "LINK_DEFINING_TUS_LISTED_IN_BOTH_TARGETS" ($need.Count - $missing.Count)
foreach ($m in $missing) { "    MISSING: $m" }
Bump "LINK_DEFINING_TUS_MISSING_FROM_A_TARGET" $missing.Count

# --- Build receipts (recorded, not re-run here) ---------------------------
$exe = "$root\build_q2check\rawr_monolith.exe"
Say "RAWR_MONOLITH_BINARY_PRESENT" (Test-Path $exe)
if (Test-Path $exe) { Say "RAWR_MONOLITH_BINARY_BYTES" (Get-Item $exe).Length }
Bump "RAWR_MONOLITH_BINARY_ABSENT" ([int](-not (Test-Path $exe)))

Write-Host "-----------------------------------------------------------------"
Write-Host "Q2_5_FAIL=$fail"
Write-Host "VERDICT=$(if ($fail -eq 0) { 'PASS' } else { 'FAIL' })"
exit $(if ($fail -eq 0) { 0 } else { 1 })
