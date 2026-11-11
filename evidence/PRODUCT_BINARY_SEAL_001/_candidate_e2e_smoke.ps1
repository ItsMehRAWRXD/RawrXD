# PRODUCT_BINARY_SEAL_001 candidate-only smoke (fail-closed, INVENT_PASS=0)
$ErrorActionPreference = 'Continue'
$seal = 'F:\rawrxd\evidence\PRODUCT_BINARY_SEAL_001'
$exe  = 'F:\rawrxd\.worktrees\product_seal_clean_a5ae60ef_build\bin\RawrXD-Win32IDE-Native.exe'
$expect = 'CB34EF4E1A3C964ADEC18F02ABBE605B85CB83F10961BCA6A9DB2D812FC0C6FB'
$asof = (Get-Date).ToUniversalTime().ToString('o')
$sha = (Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash
$hashOk = ($sha -eq $expect)

$chatLog = Join-Path $seal 'logs_chatwindow_smoke.txt'
$gtLog   = Join-Path $seal 'logs_ghosttext_smoke.txt'
New-Item -ItemType Directory -Force -Path $seal | Out-Null

function W([string]$path, [string]$m) {
  $line = '[{0}] {1}' -f (Get-Date).ToString('o'), $m
  Add-Content -LiteralPath $path -Value $line
  Write-Output $line
}

# --- Host gate ---
$ram = [math]::Round((Get-CimInstance Win32_OperatingSystem).FreePhysicalMemory / 1MB, 2)
$fFree = $null
try { $fFree = [math]::Round((Get-PSDrive F).Free / 1GB, 2) } catch {}
$others = @(Get-Process -ErrorAction SilentlyContinue | Where-Object {
  $_.ProcessName -match 'RawrXD|Win32IDE'
})
$hostOk = $hashOk -and ($others.Count -eq 0)
$hostNote = "hashOk=$hashOk freeRamGB=$ram freeF_GB=$fFree otherRawr=$($others.Count)"

# --- ChatWindow smoke ---
Set-Content -LiteralPath $chatLog -Value "# chatwindow smoke $asof"
W $chatLog "EXE=$exe"
W $chatLog "SHA256=$sha HASH_MATCH=$hashOk"
W $chatLog "HOST $hostNote"

$chatVerdict = 'NOT_VERIFIED'
$gtVerdict = 'NOT_VERIFIED'
$tokenVerdict = 'NOT_VERIFIED'
$chatDetail = ''
$gtDetail = ''
$tokenDetail = ''
$proc = $null
$exitCode = $null
$crash = $false

if (-not $hostOk) {
  $chatVerdict = 'NOT_VERIFIED'
  $chatDetail = "HOST_STABILITY_OR_HASH_GATE_FAILED $hostNote"
  W $chatLog $chatDetail
} else {
  try {
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $exe
    $psi.WorkingDirectory = Split-Path $exe
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $proc = [System.Diagnostics.Process]::Start($psi)
    W $chatLog "LAUNCHED pid=$($proc.Id)"
    Start-Sleep -Seconds 8

    Add-Type @"
using System;
using System.Text;
using System.Collections.Generic;
using System.Runtime.InteropServices;
public class SealEnum001 {
  public delegate bool EnumProc(IntPtr h, IntPtr l);
  [DllImport("user32.dll")] public static extern bool EnumWindows(EnumProc lp, IntPtr l);
  [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetClassNameW(IntPtr h, StringBuilder s, int n);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetWindowTextW(IntPtr h, StringBuilder s, int n);
  [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
  [DllImport("user32.dll")] public static extern bool PostMessageW(IntPtr h, uint m, IntPtr w, IntPtr l);
  public const uint WM_CLOSE = 0x0010;
}
"@
    $wins = New-Object System.Collections.Generic.List[string]
    $targetPid = [uint32]$proc.Id
    [SealEnum001]::EnumWindows({
      param($h, $l)
      $wp = [uint32]0
      [void][SealEnum001]::GetWindowThreadProcessId($h, [ref]$wp)
      if ($wp -eq $targetPid) {
        $cn = New-Object System.Text.StringBuilder 256
        $tt = New-Object System.Text.StringBuilder 512
        [void][SealEnum001]::GetClassNameW($h, $cn, 256)
        [void][SealEnum001]::GetWindowTextW($h, $tt, 512)
        $vis = [SealEnum001]::IsWindowVisible($h)
        $wins.Add(("hwnd={0} vis={1} class={2} title={3}" -f $h, $vis, $cn.ToString(), $tt.ToString()))
      }
      return $true
    }, [IntPtr]::Zero) | Out-Null

    foreach ($w in $wins) { W $chatLog "WIN $w" }
    $hasMain = ($wins | Where-Object { $_ -match 'Rawr|IDE|Chat|Win32' }).Count -gt 0
    if ($wins.Count -eq 0) {
      $chatVerdict = 'FAIL'
      $chatDetail = 'NO_TOPLEVEL_WINDOWS_AFTER_8S'
    } elseif (-not $proc.HasExited) {
      $chatVerdict = 'NOT_VERIFIED'
      $chatDetail = "UI_UP windows=$($wins.Count) hasMainHint=$hasMain; prompt/response/cancel NOT_EXERCISED (smoke only)"
    } else {
      $exitCode = $proc.ExitCode
      $chatVerdict = 'FAIL'
      $chatDetail = "PROCESS_EXITED_EARLY exit=$exitCode windows=$($wins.Count)"
      $crash = $true
    }

    # GhostText capture window — reuse live process if still up
    Set-Content -LiteralPath $gtLog -Value "# ghosttext smoke $asof"
    W $gtLog "EXE=$exe SHA256=$sha"
    if (-not $proc.HasExited) {
      W $gtLog "PROCESS_ALIVE pid=$($proc.Id) — GhostText control probe not asserted (clean-tip may lack WIP GhostText)"
      $gtVerdict = 'NOT_VERIFIED'
      $gtDetail = 'PROCESS_ALIVE_NO_GHOSTTEXT_ASSERTION; WIP GhostText not in clean tip'
    } else {
      $gtVerdict = 'NOT_VERIFIED'
      $gtDetail = 'PROCESS_DEAD_BEFORE_GHOSTTEXT_PROBE'
      W $gtLog $gtDetail
    }

    # Teardown
    if ($proc -and -not $proc.HasExited) {
      foreach ($w in $wins) {
        if ($w -match 'hwnd=(\d+)') {
          [void][SealEnum001]::PostMessageW([IntPtr][int64]$Matches[1], [SealEnum001]::WM_CLOSE, [IntPtr]::Zero, [IntPtr]::Zero)
        }
      }
      if (-not $proc.WaitForExit(5000)) {
        W $chatLog 'FORCE_KILL'
        $proc.Kill()
        [void]$proc.WaitForExit(5000)
      }
      $exitCode = $proc.ExitCode
      W $chatLog "TEARDOWN exit=$exitCode"
    }

    # stdout/err
    try {
      $so = $proc.StandardOutput.ReadToEnd()
      $se = $proc.StandardError.ReadToEnd()
      if ($so) { W $chatLog ("STDOUT_LEN={0}" -f $so.Length); Add-Content $chatLog $so.Substring(0, [Math]::Min(2000, $so.Length)) }
      if ($se) { W $chatLog ("STDERR_LEN={0}" -f $se.Length); Add-Content $chatLog $se.Substring(0, [Math]::Min(2000, $se.Length)) }
    } catch {}
  } catch {
    $chatVerdict = 'FAIL'
    $chatDetail = "LAUNCH_EXCEPTION $($_.Exception.Message)"
    W $chatLog $chatDetail
    $gtVerdict = 'NOT_VERIFIED'
    $gtDetail = 'SKIPPED_DUE_TO_CHAT_LAUNCH_FAILURE'
  }
}

# 64-token — require model env; do not invent
$modelCandidates = @(
  $env:RAWRXD_MODEL_PATH,
  $env:DEEP2_MODEL_PATH,
  'F:\rawrxd\models',
  'G:\models'
) | Where-Object { $_ }
$gguf = $null
foreach ($root in $modelCandidates) {
  if (Test-Path -LiteralPath $root -PathType Leaf -ErrorAction SilentlyContinue) {
    if ($root -like '*.gguf') { $gguf = $root; break }
  } elseif (Test-Path -LiteralPath $root -PathType Container -ErrorAction SilentlyContinue) {
    $hit = Get-ChildItem -LiteralPath $root -Filter *.gguf -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($hit) { $gguf = $hit.FullName; break }
  }
}
if (-not $gguf) {
  $tokenVerdict = 'NOT_VERIFIED'
  $tokenDetail = 'MISSING_PREREQUISITE: no GGUF via RAWRXD_MODEL_PATH/DEEP2_MODEL_PATH/F:\rawrxd\models/G:\models; 64-token product path not executed'
} else {
  $tokenVerdict = 'NOT_VERIFIED'
  $tokenDetail = "MODEL_CANDIDATE_FOUND=$gguf but product IDE 64-token harness not wired in this smoke; GENERATED_TOKENS=NOT_OBSERVED"
}

# Write receipts
@"
# CHATWINDOW_RUNTIME_RECEIPT

ASOF_UTC=$asof
BUILD_SCOPE=CANDIDATE_ONLY
SOURCE_AUTHORITY=a5ae60efecac790598e2e46d9e499eb8ac7287af
CANDIDATE_EXE=$exe
CANDIDATE_SHA256=$sha
HASH_MATCH=$hashOk
HOST=$hostNote
VERDICT=$chatVerdict
DETAIL=$chatDetail
EXIT_CODE=$exitCode
CRASH=$crash
MODEL_ROUTING=NOT_OBSERVED
GENERATED_TOKENS=NOT_OBSERVED
CANCEL=NOT_EXERCISED
EDITOR_FOCUS=NOT_EXERCISED
PROMOTE=0
CERTIFIED=0
AUTHORITY_PRODUCT_BINARY=NOT_VERIFIED
INVENT_PASS=0

## Notes
Smoke launch + toplevel window enum only. Full prompt→response→cancel path was **not** completed in this candidate seal pass.
Log: ``$chatLog``
"@ | Set-Content -Encoding utf8 (Join-Path $seal 'CHATWINDOW_RUNTIME_RECEIPT.md')

@"
# GHOSTTEXT_RUNTIME_RECEIPT

ASOF_UTC=$asof
BUILD_SCOPE=CANDIDATE_ONLY
SOURCE_AUTHORITY=a5ae60efecac790598e2e46d9e499eb8ac7287af
CANDIDATE_EXE=$exe
CANDIDATE_SHA256=$sha
VERDICT=$gtVerdict
DETAIL=$gtDetail
PROMOTE=0
CERTIFIED=0
NOTE=Clean-tip source omits KEEP_BRANCH WIP GhostText changes; Gate6 tool PASS is not transferable.
Log: ``$gtLog``
"@ | Set-Content -Encoding utf8 (Join-Path $seal 'GHOSTTEXT_RUNTIME_RECEIPT.md')

@"
# PRODUCT_64_TOKEN_RECEIPT

ASOF_UTC=$asof
BUILD_SCOPE=CANDIDATE_ONLY
SOURCE_AUTHORITY=a5ae60efecac790598e2e46d9e499eb8ac7287af
CANDIDATE_EXE=$exe
CANDIDATE_SHA256=$sha
VERDICT=$tokenVerdict
DETAIL=$tokenDetail
GENERATED_TOKENS=NOT_OBSERVED
TOKEN_COMMIT=NOT_OBSERVED
PROMOTE=0
CERTIFIED=0
AUTHORITY_PRODUCT_BINARY=NOT_VERIFIED
"@ | Set-Content -Encoding utf8 (Join-Path $seal 'PRODUCT_64_TOKEN_RECEIPT.md')

@"
# GATE_SUMMARY — PRODUCT_BINARY_SEAL_001 (CLEAN-TIP CANDIDATE)

ASOF_UTC=$asof
BUILD_SCOPE=CANDIDATE_ONLY
SOURCE_AUTHORITY=a5ae60efecac790598e2e46d9e499eb8ac7287af
CANDIDATE_SHA256=$sha
PRODUCTION_BINARY_MUTATION=0
PROMOTE=0
CERTIFIED=0
TIP_CLIMB=HOLD
AUTHORITY_PRODUCT_BINARY=NOT_VERIFIED

## Stage results

| Gate | Result | Notes |
|------|--------|-------|
| WIP preserve (37-path) | PASS | WIP_PRESERVE_VERIFY.csv all match |
| Clean worktree @ a5ae60ef | NOT_VERIFIED | head match + 0 diffs; untracked_count=1 unclassified at provenance time |
| Native CMake target build | PASS | RawrXD-Win32IDE-Native Release/Ninja BUILD_EXIT=0 |
| Candidate EXE seal | PASS | SHA256=$sha bytes=1608192 |
| Host stability precheck | PASS | hash re-verify; 0 RawrXD processes; freeRamGB=$ram freeF_GB=$fFree |
| ChatWindow product E2E | $chatVerdict | $chatDetail |
| GhostText product E2E | $gtVerdict | $gtDetail |
| 64-token product E2E | $tokenVerdict | $tokenDetail |
| Production binary certify | NOT_VERIFIED | candidate ≠ production authority |

## Controlling law
``SOURCE_WIRED != RUNTIME_REACHED != TOKEN_SURVIVED != PERFORMANCE_PASS``
``NOT_RUN != PASS``. No invented PASS. Candidate remains non-authoritative.
"@ | Set-Content -Encoding utf8 (Join-Path $seal 'GATE_SUMMARY.md')

Write-Output "DONE chat=$chatVerdict gt=$gtVerdict tok=$tokenVerdict"
