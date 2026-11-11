$ErrorActionPreference = 'Continue'
$ev = 'F:\rawrxd\evidence\RAWRXD_GIT_RECOVERY_001'
$out = Join-Path $ev 'sibling_odb_inventory.txt'
$lines = @("=== sibling ODB inventory $(Get-Date -Format o)")

$candidates = @(
  'F:\rawrxd',
  'F:\rawrxd-native-agent-001',
  'F:\rawrxd_stagea',
  'F:\~dev\rawrxd',
  'G:\rawrxd',
  'G:\rawrxd-push-tmp',
  'G:\~dev\rawrxd',
  'G:\VSC0de\rawrxd'
)

function Resolve-GitDir([string]$path) {
  if (-not (Test-Path -LiteralPath $path)) { return $null }
  $git = Join-Path $path '.git'
  if (Test-Path -LiteralPath $git -PathType Leaf) {
    $txt = (Get-Content -LiteralPath $git -Raw).Trim()
    if ($txt -match '^gitdir:\s*(.+)$') {
      $gd = $Matches[1].Trim()
      if (-not [IO.Path]::IsPathRooted($gd)) { $gd = Join-Path $path $gd }
      $rp = Resolve-Path -LiteralPath $gd -ErrorAction SilentlyContinue
      if ($rp) { return $rp.Path }
      return $null
    }
  }
  if (Test-Path -LiteralPath (Join-Path $git 'objects')) { return (Resolve-Path -LiteralPath $git).Path }
  return $null
}

foreach ($c in $candidates) {
  $gd = Resolve-GitDir $c
  $lines += "WORKTREE=$c"
  if ($gd) {
    $obj = Join-Path $gd 'objects'
    $lines += "  GITDIR=$gd"
    $lines += "  OBJECTS=$(Test-Path -LiteralPath $obj)"
    $packCount = 0
    $looseHint = 0
    if (Test-Path -LiteralPath $obj) {
      $packDir = Join-Path $obj 'pack'
      if (Test-Path -LiteralPath $packDir) {
        $packCount = @(Get-ChildItem -LiteralPath $packDir -Filter '*.pack' -ErrorAction SilentlyContinue).Count
      }
      $ae = Join-Path $obj 'ae\5bcf93cdf1504412826147509691ebc4689a77'
      $lines += "  HAS_ae5bcf93_LOOSE=$(Test-Path -LiteralPath $ae)"
    }
    $lines += "  PACK_COUNT=$packCount"
  } else {
    $lines += "  GITDIR=MISSING_OR_UNREADABLE"
  }
  $lines += '---'
}

# Also scan F:\~dev for nested .git/objects containing ae5bcf93 prefix folder
$targetLoose = 'ae\5bcf93cdf1504412826147509691ebc4689a77'
$searchRoots = @('F:\~dev', 'F:\rawrxd\.git\objects', 'G:\~dev')
foreach ($root in $searchRoots) {
  if (-not (Test-Path -LiteralPath $root)) { $lines += "SEARCH_ROOT_MISSING=$root"; continue }
  $lines += "SEARCH_ROOT=$root"
  try {
    $hit = Get-ChildItem -LiteralPath $root -Recurse -Filter '5bcf93cdf1504412826147509691ebc4689a77' -ErrorAction SilentlyContinue |
      Select-Object -First 20
    foreach ($h in $hit) { $lines += "  HIT=$($h.FullName)" }
    if (-not $hit) { $lines += '  HIT=none' }
  } catch {
    $lines += "  SEARCH_ERROR=$($_.Exception.Message)"
  }
}

# Check whether object exists via git cat-file in each readable repo
foreach ($c in $candidates) {
  if (-not (Test-Path -LiteralPath $c)) { continue }
  $probe = & git -C $c cat-file -t ae5bcf93cdf1504412826147509691ebc4689a77 2>&1
  $lines += "CATFILE $c => $probe (exit=$LASTEXITCODE)"
}

$lines | Set-Content -LiteralPath $out -Encoding UTF8
Get-Content -LiteralPath $out
