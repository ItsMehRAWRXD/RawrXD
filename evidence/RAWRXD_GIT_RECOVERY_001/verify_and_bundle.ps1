$ErrorActionPreference = 'Continue'
$ev = 'F:\rawrxd\evidence\RAWRXD_GIT_RECOVERY_001'
$repo = 'F:\rawrxd'
$iso = 'F:\rawrxd_recovery_iso_001'
$bundle = Join-Path $ev 'rawrxd_full_recovery.bundle'
$lines = New-Object 'System.Collections.Generic.List[string]'
function AddL([string]$s) { [void]$lines.Add($s); Write-Output $s }

AddL('=== verify_and_bundle ' + (Get-Date -Format o))

# --- fsck with reflogs ---
$sw = [Diagnostics.Stopwatch]::StartNew()
$psi = New-Object Diagnostics.ProcessStartInfo
$psi.FileName = 'git'
$psi.Arguments = '-C "' + $repo + '" fsck --full'
$psi.RedirectStandardOutput = $true
$psi.RedirectStandardError = $true
$psi.UseShellExecute = $false
$psi.CreateNoWindow = $true
$p = [Diagnostics.Process]::Start($psi)
$out = $p.StandardOutput.ReadToEnd()
$err = $p.StandardError.ReadToEnd()
$p.WaitForExit()
$sw.Stop()
$out | Set-Content (Join-Path $ev 'fsck_post_recovery_stdout.txt') -Encoding UTF8
$err | Set-Content (Join-Path $ev 'fsck_post_recovery_stderr.txt') -Encoding UTF8
$miss = ([regex]::Matches($out, 'missing\s+(?:blob|tree|commit|tag)\s+[0-9a-f]{40}')).Count
AddL('FSCK_FULL_PID=' + $p.Id)
AddL('FSCK_FULL_EXIT=' + $p.ExitCode)
AddL('FSCK_FULL_ELAPSED_MS=' + $sw.ElapsedMilliseconds)
AddL('FSCK_FULL_MISSING_LINES=' + $miss)
AddL('FSCK_FULL_STDERR=' + $err.Trim())

# --- fsck without reflogs ---
$sw2 = [Diagnostics.Stopwatch]::StartNew()
$psi2 = New-Object Diagnostics.ProcessStartInfo
$psi2.FileName = 'git'
$psi2.Arguments = '-C "' + $repo + '" fsck --full --no-reflogs'
$psi2.RedirectStandardOutput = $true
$psi2.RedirectStandardError = $true
$psi2.UseShellExecute = $false
$psi2.CreateNoWindow = $true
$p2 = [Diagnostics.Process]::Start($psi2)
$out2 = $p2.StandardOutput.ReadToEnd()
$err2 = $p2.StandardError.ReadToEnd()
$p2.WaitForExit()
$sw2.Stop()
$out2 | Set-Content (Join-Path $ev 'fsck_post_recovery_noreflogs_stdout.txt') -Encoding UTF8
$err2 | Set-Content (Join-Path $ev 'fsck_post_recovery_noreflogs_stderr.txt') -Encoding UTF8
$miss2 = ([regex]::Matches($out2, 'missing\s+(?:blob|tree|commit|tag)\s+[0-9a-f]{40}')).Count
AddL('FSCK_NORELOG_EXIT=' + $p2.ExitCode)
AddL('FSCK_NORELOG_ELAPSED_MS=' + $sw2.ElapsedMilliseconds)
AddL('FSCK_NORELOG_MISSING_LINES=' + $miss2)

# --- rawrxda/HEAD ---
$headPath = Join-Path $repo '.git\refs\remotes\rawrxda\HEAD'
$headBefore = (Get-Content -LiteralPath $headPath -Raw).Trim()
$sym = (& git -C $repo symbolic-ref refs/remotes/rawrxda/HEAD 2>&1 | Out-String).Trim()
$symExit = $LASTEXITCODE
$targetExists = $false
if ($sym -match '^refs/') {
  & git -C $repo show-ref --verify --quiet $sym
  $targetExists = ($LASTEXITCODE -eq 0)
}
AddL('RAWRXDA_HEAD_FILE=' + $headBefore)
AddL('RAWRXDA_HEAD_SYMBOLIC_REF=' + $sym)
AddL('RAWRXDA_HEAD_SYMBOLIC_EXIT=' + $symExit)
AddL('RAWRXDA_HEAD_TARGET_EXISTS=' + $targetExists)
# Preserve existing value; repair only if broken.
if ($symExit -ne 0 -or -not $targetExists) {
  $preferred = 'refs/remotes/rawrxda/main'
  & git -C $repo show-ref --verify --quiet $preferred
  if ($LASTEXITCODE -ne 0) { $preferred = 'refs/remotes/rawrxda/backup/20260316-ide' }
  & git -C $repo show-ref --verify --quiet $preferred
  if ($LASTEXITCODE -eq 0) {
    # rewrite symbolic ref without moving branch tips
    Set-Content -LiteralPath $headPath -Value ("ref: " + $preferred + "`n") -Encoding ASCII -NoNewline
    AddL('RAWRXDA_HEAD_REPAIRED_TO=' + $preferred)
  } else {
    AddL('RAWRXDA_HEAD_REPAIR_SKIPPED_NO_VALID_TARGET')
  }
} else {
  AddL('RAWRXDA_HEAD_STATUS=VALID_PRESERVED')
}
$headAfter = (Get-Content -LiteralPath $headPath -Raw).Trim()
AddL('RAWRXDA_HEAD_AFTER=' + $headAfter)

# --- dirty worktree snapshot (not in bundle) ---
$status = & git -C $repo status --porcelain=v1 2>&1
$status | Set-Content (Join-Path $ev 'dirty_worktree_porcelain.txt') -Encoding UTF8
AddL('DIRTY_PORCELAIN_LINES=' + @($status).Count)
AddL('DIRTY_PRESERVED_SEPARATELY=1')

# --- full bundle (only if missing==0) ---
if ($miss -eq 0 -and $miss2 -eq 0) {
  AddL('BUNDLE_START')
  $sw3 = [Diagnostics.Stopwatch]::StartNew()
  & git -C $repo bundle create $bundle --all 2>&1 | Set-Content (Join-Path $ev 'bundle_create_stderr.txt') -Encoding UTF8
  $bundleExit = $LASTEXITCODE
  $sw3.Stop()
  AddL('BUNDLE_EXIT=' + $bundleExit)
  AddL('BUNDLE_ELAPSED_MS=' + $sw3.ElapsedMilliseconds)
  if (Test-Path -LiteralPath $bundle) {
    AddL('BUNDLE_BYTES=' + (Get-Item -LiteralPath $bundle).Length)
    & git bundle verify $bundle 2>&1 | Set-Content (Join-Path $ev 'bundle_verify.txt') -Encoding UTF8
    AddL('BUNDLE_VERIFY_EXIT=' + $LASTEXITCODE)
  } else {
    AddL('BUNDLE_MISSING_FILE=1')
  }

  if ($bundleExit -eq 0 -and (Test-Path -LiteralPath $bundle)) {
    if (Test-Path -LiteralPath $iso) {
      AddL('ISO_EXISTS_REUSING=' + $iso)
    } else {
      New-Item -ItemType Directory -Path $iso | Out-Null
      & git -C $iso init 2>&1 | Out-Null
    }
    & git -C $iso fetch $bundle 'refs/*:refs/*' 2>&1 | Set-Content (Join-Path $ev 'iso_fetch.txt') -Encoding UTF8
    AddL('ISO_FETCH_EXIT=' + $LASTEXITCODE)
    $srcRefs = & git -C $repo for-each-ref --format='%(objectname) %(refname)' 2>$null | Sort-Object
    $isoRefs = & git -C $iso for-each-ref --format='%(objectname) %(refname)' 2>$null | Sort-Object
    $srcRefs | Set-Content (Join-Path $ev 'canonical_refs.txt') -Encoding UTF8
    $isoRefs | Set-Content (Join-Path $ev 'iso_refs.txt') -Encoding UTF8
    $srcSet = [System.Collections.Generic.HashSet[string]]::new([string[]]$srcRefs)
    $isoSet = [System.Collections.Generic.HashSet[string]]::new([string[]]$isoRefs)
    $onlySrc = @($srcRefs | Where-Object { -not $isoSet.Contains($_) })
    $onlyIso = @($isoRefs | Where-Object { -not $srcSet.Contains($_) })
    $onlySrc | Set-Content (Join-Path $ev 'refs_only_in_canonical.txt') -Encoding UTF8
    $onlyIso | Set-Content (Join-Path $ev 'refs_only_in_iso.txt') -Encoding UTF8
    AddL('REF_COMPARE_CANONICAL_COUNT=' + $srcRefs.Count)
    AddL('REF_COMPARE_ISO_COUNT=' + $isoRefs.Count)
    AddL('REF_ONLY_CANONICAL=' + $onlySrc.Count)
    AddL('REF_ONLY_ISO=' + $onlyIso.Count)
    if ($onlySrc.Count -eq 0 -and $onlyIso.Count -eq 0) { AddL('REF_COMPARE=MATCH') }
    else { AddL('REF_COMPARE=DIVERGE') }
  }
} else {
  AddL('BUNDLE_BLOCKED_MISSING_OBJECTS')
  AddL('GITHUB_PUBLICATION=BLOCKED')
}

AddL('SCOPE_NOTE=fsck_certifies_scanned_reachable_graph_not_every_historical_object_ever_created')
AddL('PROMOTE=0')
$lines | Set-Content (Join-Path $ev 'verify_and_bundle_summary.txt') -Encoding UTF8
