# Self-contained SHA-256 for Windows PowerShell and PowerShell 7 hosts.
# Avoids relying on a host-specific PSModulePath when invoked from build tools.
function Get-FileHash {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$LiteralPath,
          [ValidateSet('SHA256')][string]$Algorithm = 'SHA256')
    $resolved = (Resolve-Path -LiteralPath $LiteralPath).Path
    $stream = [IO.File]::OpenRead($resolved)
    $hasher = [Security.Cryptography.SHA256]::Create()
    try {
        $hash = [BitConverter]::ToString($hasher.ComputeHash($stream)).Replace('-', '')
        [pscustomobject]@{Algorithm = $Algorithm; Hash = $hash; Path = $resolved}
    } finally { $hasher.Dispose(); $stream.Dispose() }
}
