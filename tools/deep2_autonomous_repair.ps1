# ============================================================================
# deep2_autonomous_repair.ps1  --  RAWR_AUTONOMOUS_REPAIR_E2E_001
# ----------------------------------------------------------------------------
# Autonomous repair challenge driver.
#
# Seeds an UNDISCLOSED repository defect into a fresh workspace (the model is
# told only the symptom, never the cause or the fix), runs the Deep2 native
# agentic loop (inference -> tool call -> execution -> observation -> resumed
# inference), and certifies the outcome with INDEPENDENT gates:
#
#   [R1] INSPECTION   the model actually read the defective file before
#                     proposing anything (a read tool call is in the log).
#   [R2] EDIT         the model wrote a candidate fix (write tool call).
#   [R3] BUILD        the model invoked a build command (bash tool call).
#   [R4] TEST         the model invoked a run/test command (bash).
#   [R5] SELF-CORRECTION the loop ran more than the minimum helpful steps, or
#                     recovered from a failed attempt (>= 4 dispatched steps,
#                     or a FAIL/failed observation followed by a retry).
#   [R6] INDEPENDENT SOURCE the harness itself (not the model) confirms the
#                     defect is gone from the on-disk source.
#   [R7] INDEPENDENT BUILD+RUN the harness itself builds the repaired source
#                     with the documented toolchain and runs the binary,
#                     requiring exit 0 and the expected PASS output.
#   [R8] VERDICT      the loop's own independent verification passed.
#
# The defect family is rotated by -Defect so the challenge is not a one-shot
# memorised repair. Every gate is fail-closed; a gate that cannot be evaluated
# (e.g. the loop never got that far) is a FAIL, not a skip.
# ============================================================================
param(
    [Parameter(Mandatory=$true)][string]$Model,
    [string]$Workdir = "agentic_repair_ws",
    [string]$Evidence = "evidence/deep2_autonomous_repair",
    [ValidateSet("sign_flip","off_by_one","wrong_operator")][string]$Defect = "sign_flip",
    [int]$MaxSteps = 12,
    [int]$MaxNew = 200,
    [int]$TimeoutSec = 3600
)
$ErrorActionPreference = "Stop"
Set-Location -LiteralPath $PSScriptRoot\..
# The MSVC toolchain is only on PATH inside a developer environment; both the
# seeding self-check and the independent build gate compile with `cl`. Rather
# than importing vcvars' environment into this session (fragile across
# PowerShell versions), every compile runs through one cmd wrapper that loads
# the developer environment first.
$vcvars = "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvarsall.bat"
if (-not (Test-Path $vcvars)) {
    Write-Host "TOOLCHAIN-FAIL: vcvarsall.bat not found at $vcvars; a build-gated challenge cannot run."
    exit 2
}
function Invoke-Build([string]$dir, [string]$srcName) {
    # Compiles $dir/$srcName into $dir/calc.exe inside a developer environment
    # and returns the combined compiler+run output (including EXITCODE=...).
    $cmd = "`"$vcvars`" x64 >nul 2>&1 && cd /d `"$([System.IO.Path]::GetFullPath($dir))`" && del /q calc.exe 2>nul & cl /nologo /std:c++20 /EHsc /O2 $srcName /Fe:calc.exe 2>&1 & if exist calc.exe (calc.exe & echo EXITCODE=%ERRORLEVEL%) else (echo COMPILE_FAILED)"
    return ((cmd /c $cmd) 2>&1 | Out-String)
}

New-Item -ItemType Directory -Force -Path $Evidence | Out-Null
New-Item -ItemType Directory -Force -Path $Workdir | Out-Null

# ---- seed the undisclosed defect ------------------------------------------
# The model is told ONLY the symptom in task.md. The seeded source carries the
# defect; no comment, log line, or task text reveals the cause or the fix.
function Seed-Defect([string]$kind) {
    switch ($kind) {
        "sign_flip" {
            # Reads as a plausible addition; the second operand's sign is
            # silently inverted. add(2,3) == -1.
            @"
#include <cstdio>
int add(int a, int b) {
    return a + -b;
}
int main() {
    if (add(2, 3) == 5) {
        printf("PASS\n");
    } else {
        printf("FAIL add(2,3)=%d\n", add(2, 3));
    }
    return 0;
}
"@
        }
        "off_by_one" {
            # An accumulation loop whose bound is one short.
            @"
#include <cstdio>
int add(int a, int b) {
    int r = a;
    for (int i = 0; i < b - 1; ++i) ++r;
    return r;
}
int main() {
    if (add(2, 3) == 5) {
        printf("PASS\n");
    } else {
        printf("FAIL add(2,3)=%d\n", add(2, 3));
    }
    return 0;
}
"@
        }
        "wrong_operator" {
            # Subtraction written where addition belongs.
            @"
#include <cstdio>
int add(int a, int b) {
    return a - b + 2 * 0;
}
int main() {
    if (add(2, 3) == 5) {
        printf("PASS\n");
    } else {
        printf("FAIL add(2,3)=%d\n", add(2, 3));
    }
    return 0;
}
"@
        }
    }
}

# The seeded source must actually FAIL its own self-test before the loop runs
# (otherwise the "repair" is a no-op and the challenge certifies nothing).
$seedSrc = Seed-Defect $Defect
Set-Content -LiteralPath "$Workdir/calc.cpp" -Value $seedSrc -NoNewline -Encoding ascii
@"
The self-test in this workspace fails: running .\calc.exe currently prints FAIL.
Make the self-test print PASS. Build with: cl /nologo /std:c++20 /EHsc /O2 calc.cpp /Fe:calc.exe
"@ | Set-Content -LiteralPath "$Workdir/task.md" -Encoding ascii

Write-Host "=== RAWR_AUTONOMOUS_REPAIR_E2E_001 ==="
Write-Host "model   : $Model"
Write-Host "workdir : $Workdir"
Write-Host "defect  : $Defect (undisclosed to the model; only the symptom is given)"

# ---- confirm the seeded defect really fails --------------------------------
$seedOut = Invoke-Build $Workdir "calc.cpp"
$seedFailed = ($seedOut -match "FAIL")
$seedCompiled = ($seedOut -notmatch "COMPILE_FAILED")
Write-Host "seeded defect compiles : $seedCompiled"
Write-Host "seeded defect fails    : $seedFailed (self-test: $(($seedOut -split "`n" | Where-Object { $_ -match 'PASS|FAIL|EXIT|COMPILE' }) -join ' '))"
if (-not $seedFailed) {
    Write-Host "CHALLENGE-SETUP-FAIL: the seeded defect does not fail its self-test; the challenge would certify a no-op."
    exit 2
}

# ---- run the agentic loop ---------------------------------------------------
$loopLog = Join-Path $Evidence "agentic_loop.log"
$loopExe = Join-Path $PSScriptRoot "deep2_agentic_loop.exe"
Write-Host ""
Write-Host "--- running Deep2 native agentic loop (max $MaxSteps steps) ---"
$psi = New-Object System.Diagnostics.ProcessStartInfo
$psi.FileName = $loopExe
$psi.Arguments = "--model `"$Model`" --workdir `"$Workdir`" --max-steps $MaxSteps --max-new $MaxNew"
$psi.WorkingDirectory = $PSScriptRoot
$psi.RedirectStandardOutput = $true
$psi.RedirectStandardError = $true
$psi.UseShellExecute = $false
$p = [System.Diagnostics.Process]::Start($psi)
$stdout = $p.StandardOutput.ReadToEndAsync()
$stderr = $p.StandardError.ReadToEndAsync()
if (-not $p.WaitForExit($TimeoutSec * 1000)) {
    $p.Kill()
    Write-Host "LOOP_TIMEOUT after $TimeoutSec s"
}
$loopOut = $stdout.Result + "`n" + $stderr.Result
$loopExit = $p.ExitCode
Set-Content -LiteralPath $loopLog -Value $loopOut -Encoding utf8
Write-Host ($loopOut -split "`n" | Select-Object -Last 12) -join "`n"
Write-Host "loop exit code: $loopExit"

# ---- independent gates ------------------------------------------------------
$receipt = [System.Collections.Generic.List[string]]::new()
function Gate([string]$name, [bool]$ok, [string]$detail) {
    $tag = if ($ok) { "PASS" } else { "FAIL" }
    Write-Host ("  [{0}] {1} - {2}" -f $tag, $name, $detail)
    $receipt.Add(("[" + $tag + "] " + $name + " - " + $detail))
    return $ok
}

Write-Host ""
Write-Host "--- independent gates (harness-run; the model's word is not evidence) ---"

# R1..R4: the loop log records every dispatched tool with its observation.
$readCount  = ([regex]::Matches($loopOut, "TOOL read")).Count
$writeCount = ([regex]::Matches($loopOut, "TOOL write")).Count
$bashCount  = ([regex]::Matches($loopOut, "TOOL bash")).Count
$finishCount = ([regex]::Matches($loopOut, "finish")).Count
$dispatchSteps = ([regex]::Matches($loopOut, "TOOL \w+ ->")).Count

# R5 self-correction: more than the minimum dispatched steps, or an observed
# failure that was followed by another attempted action.
$observedFailure = ($loopOut -match "FAIL|error|failed|cannot|not found") -and ($dispatchSteps -ge 2)
$r5 = ($dispatchSteps -ge 4) -or ($observedFailure -and $dispatchSteps -ge 3)

# R6: the harness itself reads the on-disk source.
$srcNow = Get-Content -LiteralPath "$Workdir/calc.cpp" -Raw -ErrorAction SilentlyContinue
$r6 = ($srcNow -ne $seedSrc) -and ($srcNow -match "a\s*\+\s*b")

# R7: the harness itself builds and runs.
$r7out = Invoke-Build $Workdir "calc.cpp"
$r7exit = if ($r7out -match "EXITCODE=(\d+)") { [int]$Matches[1] } else { -999 }
$r7 = ($r7exit -eq 0) -and ($r7out -match "PASS") -and ($r7out -notmatch "COMPILE_FAILED")

# R8: the loop's own independent verdict.
$r8 = ($loopOut -match "FINAL_VERDICT\s+PASS") -and ($loopExit -eq 0)

$pass = 0; $fail = 0
if (Gate "R1 inspection : model read the defective file" ($readCount -ge 1) "read tool calls=$readCount") { $pass++ } else { $fail++ }
if (Gate "R2 edit       : model wrote a candidate fix" ($writeCount -ge 1) "write tool calls=$writeCount") { $pass++ } else { $fail++ }
if (Gate "R3 build      : model invoked a build" ($bashCount -ge 1) "bash tool calls=$bashCount") { $pass++ } else { $fail++ }
if (Gate "R4 test       : model invoked a test/run" (($loopOut -match "calc\.exe")) "run referenced in loop") { $pass++ } else { $fail++ }
if (Gate "R5 self-correction : loop iterated beyond a lucky single shot" $r5 "dispatched steps=$dispatchSteps observed_failure=$observedFailure") { $pass++ } else { $fail++ }
if (Gate "R6 indep source: defect gone from on-disk source (harness-read)" $r6 "source changed and contains a + b") { $pass++ } else { $fail++ }
if (Gate "R7 indep build+run: harness-built binary exits 0 and prints PASS" $r7 "exit=$r7exit") { $pass++ } else { $fail++ }
if (Gate "R8 loop verdict: the loop's independent verification passed" $r8 "loop exit=$loopExit") { $pass++ } else { $fail++ }

$verdict = if ($fail -eq 0) { "PASS" } else { "FAIL" }
Write-Host ""
Write-Host "pass=$pass fail=$fail"
Write-Host "FINAL_VERDICT=$verdict"

$receipt.Add("model=$Model defect=$Defect steps=$dispatchSteps loop_exit=$loopExit")
$receipt.Add("FINAL_VERDICT=$verdict")
Set-Content -LiteralPath (Join-Path $Evidence "AUTONOMOUS_REPAIR_RECEIPT.txt") -Value ($receipt -join "`n") -Encoding utf8
Write-Host "receipt: $(Join-Path $Evidence 'AUTONOMOUS_REPAIR_RECEIPT.txt')"

if ($verdict -ne "PASS") { exit 1 }
exit 0
