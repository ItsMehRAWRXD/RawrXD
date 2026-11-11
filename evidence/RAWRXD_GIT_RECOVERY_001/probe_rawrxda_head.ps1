$ErrorActionPreference = 'Continue'
$ev = 'F:\rawrxd\evidence\RAWRXD_GIT_RECOVERY_001'
$out = Join-Path $ev 'rawrxda_head_probe.txt'
$lines = @("=== rawrxda HEAD probe $(Get-Date -Format o)")

$paths = @(
  'F:\rawrxd\.git\refs\remotes\rawrxda\HEAD',
  'F:\rawrxd\.git\refs\remotes\rawrxda',
  'F:\rawrxd\.git\packed-refs'
)

foreach ($p in $paths) {
  $lines += "PATH=$p EXISTS=$(Test-Path -LiteralPath $p)"
  if (Test-Path -LiteralPath $p -PathType Leaf) {
    $lines += "CONTENT<<"
    $lines += (Get-Content -LiteralPath $p -Raw)
    $lines += ">>"
  } elseif (Test-Path -LiteralPath $p -PathType Container) {
    Get-ChildItem -LiteralPath $p -Force -ErrorAction SilentlyContinue | ForEach-Object {
      $lines += "  CHILD=$($_.Name)"
    }
  }
}

$lines += '--- git symbolic-ref ---'
$lines += (& git -C F:\rawrxd symbolic-ref refs/remotes/rawrxda/HEAD 2>&1 | Out-String)
$lines += "symbolic-ref_exit=$LASTEXITCODE"
$lines += '--- git remote show rawrxda ---'
$lines += (& git -C F:\rawrxd remote 2>&1 | Out-String)
$lines += '--- show-ref rawrxda ---'
$lines += (& git -C F:\rawrxd show-ref 2>&1 | Select-String -Pattern 'rawrxda' | Out-String)
$lines += '--- for-each-ref remotes/rawrxda ---'
$lines += (& git -C F:\rawrxd for-each-ref refs/remotes/rawrxda 2>&1 | Out-String)

$lines | Set-Content -LiteralPath $out -Encoding UTF8
Get-Content -LiteralPath $out
