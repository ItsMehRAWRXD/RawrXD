$ErrorActionPreference = 'Stop'
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$emptyDir = 'D:\rawrxd\archive\RawrXD_SOVEREIGN_BOOTSTRAP_STABLE_'
$dst = "D:\rawrxd\archive\RawrXD_SOVEREIGN_BOOTSTRAP_STABLE_$stamp"

if (Test-Path $emptyDir) { Remove-Item -Recurse -Force $emptyDir }
New-Item -ItemType Directory -Force -Path $dst | Out-Null
New-Item -ItemType Directory -Force -Path "$dst\src_asm" | Out-Null

Copy-Item D:\rawrxd\RawrXD_Engine_Sovereign.exe -Destination $dst
Copy-Item D:\rawrxd\RawrXD_Engine_Sovereign.pdb -Destination $dst -ErrorAction SilentlyContinue
Copy-Item D:\rawrxd\RawrXD_Engine_Sovereign.map -Destination $dst -ErrorAction SilentlyContinue
Copy-Item D:\rawrxd\build_pipeline_v2.bat        -Destination $dst
Copy-Item D:\rawrxd\Ingestion_Aligner.ps1        -Destination $dst -ErrorAction SilentlyContinue
Copy-Item D:\rawrxd\src\asm\*.asm                -Destination "$dst\src_asm"

& "$dst\RawrXD_Engine_Sovereign.exe" --gate-verify | Out-Null
$rcHex = '0x{0:X8}' -f ($LASTEXITCODE -band 0xFFFFFFFF)

$exeHash  = (Get-FileHash "$dst\RawrXD_Engine_Sovereign.exe" -Algorithm SHA256).Hash
$ggufHash = (Get-FileHash D:\rawrxd\phi3-mini-Q2_K.gguf      -Algorithm SHA256).Hash
$asmHashes = Get-ChildItem "$dst\src_asm\*.asm" | ForEach-Object {
    $h = (Get-FileHash $_.FullName -Algorithm SHA256).Hash
    "{0}  {1}" -f $h, $_.Name
}

$manifest = @"
RawrXD SOVEREIGN BOOTSTRAP STABLE
=================================
Frozen      : $stamp
Gate exit   : $rcHex  (expected 0xCAFEBABE)
Engine hash : $exeHash
GGUF hash   : $ggufHash
GGUF target : D:\rawrxd\phi3-mini-Q2_K.gguf
Entry       : XR_Production_Entry
Subsystem   : CONSOLE / Zero-CRT / Zero-MASM32-include
Toolchain   : ml64.exe + link.exe @ VS2022Enterprise 14.50.35717

Source-of-truth note:
  All .asm files in src_asm\ are the canonical sources. No codegen script
  regenerates them. The historical write_ingest.ps1 was a one-shot and has
  been removed. All edits go directly to .asm files.

Source ASM SHA-256:
$($asmHashes -join "`r`n")
"@
$manifest | Out-File -Encoding ASCII "$dst\MANIFEST.txt"

Write-Host ""
Write-Host "FROZEN: $dst"
Write-Host "GATE  : $rcHex"
Get-ChildItem $dst | Format-Table Name,Length,LastWriteTime
