param(
    [Parameter(Mandatory=$true)][string]$Source,
    [string]$Remote = "origin",
    [string]$Destination,
    [switch]$DryRun
)
$ErrorActionPreference = 'Stop'
if ([string]::IsNullOrWhiteSpace($Source)) { throw "BLOCKED: source ref is empty" }
if ($Source -match '^\s*:' -or $Source -match '^-' -or $Source -match '\s') {
    throw "BLOCKED: invalid source ref"
}
if ($Source -notmatch '^[A-Za-z0-9][A-Za-z0-9._/-]*$') {
    throw "BLOCKED: source ref contains unexpected characters"
}
if ([string]::IsNullOrWhiteSpace($Remote) -or $Remote -match '^-' -or $Remote -match '\s') {
    throw "BLOCKED: invalid remote"
}
if ([string]::IsNullOrWhiteSpace($Destination)) { $Destination = $Source }
if ($Destination -match '^-' -or $Destination -match '\s' -or $Destination -notmatch '^[A-Za-z0-9][A-Za-z0-9._/-]*$') {
    throw "BLOCKED: invalid destination"
}
if ($Destination -eq 'HEAD') { throw "BLOCKED: destination must be an explicit branch name" }
& git rev-parse --verify --quiet "refs/heads/$Source"
if ($LASTEXITCODE -ne 0) { throw "BLOCKED: source is not an existing local branch" }
& git check-ref-format --branch $Source | Out-Null
if ($LASTEXITCODE -ne 0) { throw "BLOCKED: invalid source branch" }
& git check-ref-format --branch $Destination | Out-Null
if ($LASTEXITCODE -ne 0) { throw "BLOCKED: invalid destination branch" }
$refspec = "refs/heads/${Source}:refs/heads/${Destination}"
Write-Host "Validated non-deleting refspec: $refspec"
if ($DryRun) { Write-Host "DRY RUN; no push"; exit 0 }
& git push -- $Remote $refspec
if ($LASTEXITCODE -ne 0) { throw "git push failed ($LASTEXITCODE)" }
