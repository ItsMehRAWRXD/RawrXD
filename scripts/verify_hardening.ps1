<#
.SYNOPSIS
    Verifies that a Windows PE binary carries the intended production security
    hardening in its headers.

.DESCRIPTION
    A compiler/linker flag being present on the command line is not proof that
    the produced binary is hardened. This script parses the PE headers of the
    supplied executables/DLLs and asserts the OS-enforced mitigations are
    actually set, then records SHA-256 digests for release integrity.

    Checks performed:
      DYNAMIC_BASE   (0x0040) - ASLR is honoured
      NX_COMPAT      (0x0100) - DEP is honoured
      HIGH_ENTROPY_VA(0x0020) - 64-bit ASLR entropy available
      GUARD_CF       (0x4000) - Control Flow Guard
      For DLLs also asserts NX_COMPAT/DYNAMIC_BASE, which are what prevent a
      downgraded from a hardened EXE load.

.PARAMETER Path
    One or more exe/dll paths to verify.

.PARAMETER Quiet
    Only print a summary line per file and the total.

.PARAMETER Json
    Emit a JSON report (for CI artifact collection).

.EXAMPLE
    .\scripts\verify_hardening.ps1 -Path .\build\bin\Release\*.exe
#>
param(
    [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
    [string[]]$Path,

    [switch]$Quiet,

    [switch]$Json
)

$ErrorActionPreference = 'Stop'
$results = @()

function Get-PeCharacteristics {
    param([string]$File)

    $bytes = [System.IO.File]::ReadAllBytes($File)
    if ($bytes.Length -lt 0x40) { throw "$File : too small to be a PE image" }

    $lfanew = [BitConverter]::ToUInt32($bytes, 0x3C)
    if ($lfanew + 24 + 6 -gt $bytes.Length) { throw "$File : bad e_lfanew 0x$($lfanew.ToString('X'))" }
    if ([Text.Encoding]::ASCII.GetString($bytes, $lfanew, 4) -ne "PE`0`0") {
        throw "$File : missing PE signature (not a Windows executable/library)"
    }

    $optOff = $lfanew + 24                      # COFF header is 20 bytes after the 4-byte PE sig
    $magic  = [BitConverter]::ToUInt16($bytes, $optOff)
    if ($magic -ne 0x20B -and $magic -ne 0x10B) {
        throw "$File : unsupported optional header magic 0x$($magic.ToString('X'))"
    }

    # Subsystem (offset 68) and DllCharacteristics (offset 70) share the same
    # offset in both PE32 and PE32+ optional headers.
    return [PSCustomObject]@{
        IsPE32Plus = ($magic -eq 0x20B)
        Subsystem  = [BitConverter]::ToUInt16($bytes, $optOff + 68)
        Characteristics = [BitConverter]::ToUInt16($bytes, $optOff + 70)
    }
}

$failed = 0
foreach ($raw in $Path) {
    # Expand glob patterns the caller could not (PowerShell passes them literally
    # when the parameter is typed as string[]).
    $files = @()
    if (Test-Path -LiteralPath $raw) { $files += (Get-Item -LiteralPath $raw) }
    else { $files += (Get-Item -Path $raw -ErrorAction SilentlyContinue) }

    foreach ($f in $files) {
        if ($f -is [System.IO.DirectoryInfo]) { continue }
        $ext = $f.Extension.ToLowerInvariant()
        if ($ext -notin @('.exe', '.dll', '.sys')) { continue }

        try {
            $pe = Get-PeCharacteristics -File $f.FullName
        } catch {
            Write-Host ("  {0,-44} ERROR: {1}" -f $f.Name, $_.Exception.Message) -ForegroundColor Red
            $failed++
            continue
        }

        $c = $pe.Characteristics
        $checks = [ordered]@{
            'DYNAMIC_BASE'    = [bool]($c -band 0x0040)
            'NX_COMPAT'       = [bool]($c -band 0x0100)
            'HIGH_ENTROPY_VA' = [bool]($c -band 0x0020)
            'GUARD_CF'        = [bool]($c -band 0x4000)
        }

        $ok = $true
        foreach ($k in $checks.Keys) {
            if (-not $checks[$k]) { $ok = $false }
        }

        if (-not $Quiet) {
            Write-Host ("  {0}" -f $f.Name)
            foreach ($k in $checks.Keys) {
                $mark = if ($checks[$k]) { 'OK  ' } else { 'MISS' }
                $color = if ($checks[$k]) { 'Green' } else { 'Red' }
                Write-Host ("    {0} {1}" -f $mark, $k) -ForegroundColor $color
            }
            Write-Host ("    PE{0}  Subsystem={1}  Characteristics=0x{2:X4}" -f
                $(if ($pe.IsPE32Plus) { '32+' } else { '32  ' }), $pe.Subsystem, $c)
        }

        $sha = (Get-FileHash -LiteralPath $f.FullName -Algorithm SHA256).Hash
        if (-not $Quiet) {
            Write-Host ("    SHA256 {0}" -f $sha) -ForegroundColor Gray
        }

        $results += [PSCustomObject]@{
            file         = $f.FullName
            size         = $f.Length
            sha256       = $sha
            pe32plus     = $pe.IsPE32Plus
            subsystem    = $pe.Subsystem
            characteristics = ('0x{0:X4}' -f $c)
            dynamic_base = $checks['DYNAMIC_BASE']
            nx_compat    = $checks['NX_COMPAT']
            high_entropy = $checks['HIGH_ENTROPY_VA']
            guard_cf     = $checks['GUARD_CF']
            hardened     = $ok
        }

        if (-not $ok) { $failed++ }
    }
}

if ($Json) {
    [PSCustomObject]@{
        generated = (Get-Date -Format 'yyyy-MM-ddTHH:mm:ssZ')
        checked   = $results.Count
        failed    = $failed
        all_hardened = ($failed -eq 0 -and $results.Count -gt 0)
        binaries  = $results
    } | ConvertTo-Json -Depth 4
}
else {
    Write-Host ''
    if ($results.Count -eq 0) {
        Write-Host 'No PE binaries matched the supplied paths.' -ForegroundColor Yellow
    } elseif ($failed -eq 0) {
        Write-Host ("HARDENING OK: all {0} binary(ies) carry ASLR+DEP+HEASLR+CFG" -f $results.Count) -ForegroundColor Green
    } else {
        Write-Host ("HARDENING FAILED: {0} of {1} binary(ies) are missing mitigations" -f $failed, $results.Count) -ForegroundColor Red
    }
}

exit $(if ($failed -gt 0) { 1 } else { 0 })
