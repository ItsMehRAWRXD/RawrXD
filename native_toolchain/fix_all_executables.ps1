# Fix All Executables - Removes malformed import tables
param([string]$TargetDir = ".")

Write-Host "================================================" -ForegroundColor Cyan
Write-Host "  EXECUTABLE FIXER - Import Table Repair" -ForegroundColor Cyan
Write-Host "================================================" -ForegroundColor Cyan
Write-Host ""

$fixed = 0
$failed = 0

Get-ChildItem $TargetDir -Filter "*.exe" | ForEach-Object {
    $exe = $_.FullName
    $name = $_.Name
    
    Write-Host "Processing: $name" -NoNewline
    
    try {
        $bytes = [System.IO.File]::ReadAllBytes($exe)
        
        # Check if PE
        if ($bytes.Length -lt 64) {
            Write-Host " (too small)" -ForegroundColor Red
            $failed++
            return
        }
        
        $dosMagic = [BitConverter]::ToUInt16($bytes, 0)
        if ($dosMagic -ne 0x5A4D) {
            Write-Host " (not PE)" -ForegroundColor Red
            $failed++
            return
        }
        
        $e_lfanew = [BitConverter]::ToInt32($bytes, 0x3C)
        if ($e_lfanew -lt 64 -or $e_lfanew -gt ($bytes.Length - 4)) {
            Write-Host " (invalid e_lfanew)" -ForegroundColor Red
            $failed++
            return
        }
        
        $peSig = [BitConverter]::ToUInt32($bytes, $e_lfanew)
        if ($peSig -ne 0x00004550) {
            Write-Host " (invalid PE sig)" -ForegroundColor Red
            $failed++
            return
        }
        
        $fileHeaderOffset = $e_lfanew + 4
        $optHeaderOffset = $fileHeaderOffset + 20
        $optionalHeaderSize = [BitConverter]::ToUInt16($bytes, $fileHeaderOffset + 16)
        
        if ($optionalHeaderSize -eq 0) {
            Write-Host " (no optional header)" -ForegroundColor Yellow
            return
        }
        
        # Check if 64-bit
        $machine = [BitConverter]::ToUInt16($bytes, $fileHeaderOffset)
        $is64Bit = ($machine -eq 0x8664)
        
        if (-not $is64Bit) {
            Write-Host " (not x64)" -ForegroundColor Yellow
            return
        }
        
        # Check import table
        $dataDirOffset = $optHeaderOffset + 112
        $importRVA = [BitConverter]::ToUInt32($bytes, $dataDirOffset + 8)
        $importSize = [BitConverter]::ToUInt32($bytes, $dataDirOffset + 12)
        
        if ($importRVA -ne 0 -or $importSize -ne 0) {
            Write-Host " (has imports: RVA=0x$($importRVA.ToString('X8')), Size=$importSize)" -ForegroundColor Yellow
            
            # Clear import table
            [Array]::Copy([byte[]](0, 0, 0, 0), 0, $bytes, $dataDirOffset + 8, 4)
            [Array]::Copy([byte[]](0, 0, 0, 0), 0, $bytes, $dataDirOffset + 12, 4)
            
            # Save backup
            $backup = $exe + ".backup"
            if (-not (Test-Path $backup)) {
                Copy-Item $exe $backup
            }
            
            # Save fixed version
            [System.IO.File]::WriteAllBytes($exe, $bytes)
            
            Write-Host " -> FIXED" -ForegroundColor Green
            $fixed++
        } else {
            Write-Host " (no imports - OK)" -ForegroundColor Green
        }
        
    } catch {
        Write-Host " (error: $_)" -ForegroundColor Red
        $failed++
    }
}

Write-Host ""
Write-Host "================================================" -ForegroundColor Cyan
Write-Host "  SUMMARY" -ForegroundColor Cyan
Write-Host "================================================" -ForegroundColor Cyan
Write-Host "Fixed: $fixed" -ForegroundColor Green
Write-Host "Failed: $failed" -ForegroundColor Red
Write-Host ""

if ($fixed -gt 0) {
    Write-Host "Backups created with .backup extension" -ForegroundColor Yellow
    Write-Host "Test the fixed executables now." -ForegroundColor Green
}
