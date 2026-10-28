#requires -Version 5.1
$ErrorActionPreference = 'Stop'
$AuthorityDir = 'G:\~dev\rawrxd\evidence\TIP_FREEZE_001\bin'
$AuthorityExe = Join-Path $AuthorityDir 'RawrXD-Win32IDE.exe'
$ExpectedSha = '748B210A8F17C6C47685BE1E2718CB0113C070E47881AD3A76B2EBB013934145'
if (-not (Test-Path -LiteralPath $AuthorityExe)) { Write-Error "TIP_EXE_MISSING path=$AuthorityExe"; exit 2 }
$sha = (Get-FileHash -LiteralPath $AuthorityExe -Algorithm SHA256).Hash
if ($sha -ne $ExpectedSha) { Write-Error "TIP_EXE_SHA_DRIFT expected=$ExpectedSha actual=$sha"; exit 3 }
$env:RAWRXD_TIP_EXE = $AuthorityExe
$env:RAWRXD_TIP_SHA = $sha
$env:RAWRXD_TIP_DIR = $AuthorityDir
$env:RAWRXD_REBUILD_THIS_DISPATCH = '0'
Write-Output "TIP_EXE_OK=$AuthorityExe"
Write-Output "TIP_SHA_OK=$sha"
Write-Output "REBUILD_THIS_DISPATCH=0"
exit 0
