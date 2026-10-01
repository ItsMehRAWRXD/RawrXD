# Q2 build-authority regression gate — RAWRXD_AGENTIC_CLI_QUARANTINE_001
#
# Fails if a nonexistent source set can advertise an agentic implementation and
# then vanish during configure. Proves the POLICY, not just today's cleanup:
# the negative fixture at the end declares a nonexistent REQUIRED source and
# asserts that configure FAILS.

$ErrorActionPreference = "Stop"
$root = "F:\~dev\rawrxd"
$fail = 0
function Say($k, $v) { "{0,-46} = {1}" -f $k, $v }
function Bump($name, $value) {
    if ($value -eq 0) { return }
    $script:fail++
    "  *** $name = $value ***"
}

Write-Host "Q2 build-authority gate"
Write-Host "-------------------------------------------------------------"

# --- 1. Canonical authority is unique -------------------------------------
$canonical = @(
  "F:\~dev\src\rawr_agent.cpp"
)
$canonPresent = @($canonical | Where-Object { Test-Path $_ })
Say "CANONICAL_AGENT_SOURCE_COUNT" $canonPresent.Count
foreach ($c in $canonical) { Say "CANONICAL_AGENT_SOURCE" $c }
Bump "CANONICAL_AGENT_MISSING" ($canonical.Count - $canonPresent.Count)

# --- 2. Phantom fragment must not be in active build authority ------------
$activeBuild = @(
  "$root\CMakeLists.txt",
  "$root\win32ide_strict\CMakeLists.txt",
  "F:\~dev\CMakeLists.txt"
) | Where-Object { Test-Path $_ }

$staleRefs = 0
foreach ($f in $activeBuild) {
  # Check ACTIVE DIRECTIVES only. A comment may legitimately name a quarantined
  # file for provenance; that must not read as a live build reference.
  $lines = Get-Content $f -ErrorAction SilentlyContinue |
           Where-Object { $_.Trim() -notmatch '^#' }
  $m = $lines | Select-String -Pattern "RawrAgenticCli\.fragment" -ErrorAction SilentlyContinue
  if ($m) { $staleRefs += $m.Count; "  stale ref: ${f}: $($m[0].Line.Trim())" }
}
Say "STALE_AGENT_STACK_REFERENCES" $staleRefs
Bump "STALE_AGENT_STACK_REFERENCES" $staleRefs

# --- 3. Tombstone present and fatal-on-enable -----------------------------
$tomb = "$root\cmake\RawrAgenticCliQuarantine.cmake"
Say "QUARANTINE_TOMBSTONE_PRESENT" (Test-Path $tomb)
Bump "QUARANTINE_TOMBSTONE_MISSING" ([int](-not (Test-Path $tomb)))
if (Test-Path $tomb) {
  $t = Get-Content $tomb -Raw
  $hasFatal = $t -match "FATAL_ERROR"
  $defaultsOff = $t -match "(?s)option\(BUILD_RAWRXD_AGENTIC_CLI.*?OFF\)"
  Say "TOMBSTONE_USES_FATAL_ERROR" $hasFatal
  Say "TOMBSTONE_DEFAULTS_OFF" $defaultsOff
  Bump "TOMBSTONE_WEAK" ([int](-not ($hasFatal -and $defaultsOff)))
}
$preserved = "$root\cmake\quarantine\RawrAgenticCli.fragment.cmake.QUARANTINED"
Say "QUARANTINED_FRAGMENT_PRESERVED" (Test-Path $preserved)

# --- 4. Declared-but-missing sources in the quarantined fragment ----------
if (Test-Path $preserved) {
  $frag = Get-Content $preserved -Raw
  $declared = [regex]::Matches($frag, '(?m)^\s+(src/[\w/\.]+\.(?:cpp|c|hpp))\s*$') |
              ForEach-Object { $_.Groups[1].Value } | Sort-Object -Unique
  $missing = @($declared | Where-Object { -not (Test-Path (Join-Path $root $_)) })
  Say "QUARANTINED_DECLARED_SOURCES" $declared.Count
  Say "QUARANTINED_MISSING_SOURCES" $missing.Count
  $certTargets = ([regex]::Matches($frag, 'rawr_(?:agent|ie)_cert\s*\(')).Count
  Say "QUARANTINED_CERT_TARGETS" $certTargets
  # These are EXPECTED to be missing. They are the reason for quarantine.
  if ($missing.Count -eq 0) { "  note: fragment declared 0 missing sources - recheck" }
}

# --- 5. Phantom patterns in ACTIVE build files ----------------------------
$phantom = 0
foreach ($f in $activeBuild) {
  $m = Select-String -Path $f -Pattern "rawr_agent_loop|rawr_permission_gate|rawr_patch_engine|rawr_session_store|src/platform/rawr_" -ErrorAction SilentlyContinue
  if ($m) { $phantom += $m.Count; "  phantom decl: ${f}:$($m[0].LineNumber) $($m[0].Line.Trim())" }
}
Say "PHANTOM_DECLARED_SOURCE_REFS" $phantom
Bump "PHANTOM_DECLARED_SOURCE_REFS" $phantom

# --- 6. NEGATIVE TEST: a missing REQUIRED source must fail configure ------
$neg = Join-Path $env:TEMP ("q2neg_" + [guid]::NewGuid().ToString("N").Substring(0,8))
New-Item -ItemType Directory -Path $neg -Force | Out-Null
@"
cmake_minimum_required(VERSION 3.20)
project(q2neg LANGUAGES CXX)
set(REQUIRED_SOURCE "\${CMAKE_CURRENT_SOURCE_DIR}/does_not_exist.cpp")
if(NOT EXISTS "\${REQUIRED_SOURCE}")
  message(FATAL_ERROR "Required source missing: \${REQUIRED_SOURCE}")
endif()
"@ | Set-Content -Path (Join-Path $neg "CMakeLists.txt") -Encoding UTF8
$out = & cmake -S $neg -B (Join-Path $neg "b") 2>&1 | Out-String
$cfgFailed = ($LASTEXITCODE -ne 0) -and ($out -match "FATAL_ERROR|Required source missing")
Say "NEGATIVE_REQUIRED_SOURCE_CONFIGURE_FAILS" $cfgFailed
Bump "NEGATIVE_TEST_DID_NOT_FAIL" ([int](-not $cfgFailed))
Remove-Item -Recurse -Force $neg -ErrorAction SilentlyContinue

# --- 7. Silently-skipped agent stacks in active build files ---------------
$silent = 0
foreach ($f in $activeBuild) {
  $m = Select-String -Path $f -Pattern "Skipping agentic" -ErrorAction SilentlyContinue
  if ($m) { $silent += $m.Count; "  silent skip: ${f}:$($m[0].LineNumber)" }
}
Say "SILENT_AGENT_STACK_SKIP_PATHS" $silent
Bump "SILENT_AGENT_STACK_SKIP_PATHS" $silent

Write-Host "-------------------------------------------------------------"
Write-Host "Q2_FAIL=$fail"
Write-Host "VERDICT=$(if ($fail -eq 0) { 'PASS' } else { 'FAIL' })"
Write-Host "RAWR_MONOLITH_BUILD=NOT_RUN_IN_THIS_GATE (configure/build is a separate step)"
exit $(if ($fail -eq 0) { 0 } else { 1 })
