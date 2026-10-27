$ErrorActionPreference = 'Continue'
$roots = @(
  'g:\~dev',
  'F:\rawrxd-native-agent-001',
  'F:\rawrxd'
)
foreach ($root in $roots) {
  Write-Output ("==== " + $root + " ====")
  if (-not (Test-Path -LiteralPath (Join-Path $root '.git'))) {
    Write-Output 'NO_GIT'
    continue
  }
  Push-Location -LiteralPath $root
  git rev-parse --show-toplevel
  git remote -v
  git status -sb
  git branch -vv | Select-Object -First 8
  Pop-Location
}
