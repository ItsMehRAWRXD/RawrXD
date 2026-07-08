# Omega-Polyglot Compiler Comprehensive Test Suite
# Tests all compilers and generates detailed report

param(
    [string]$CompilerDir = "D:\rawrxd\compilers",
    [string]$OutputDir = "D:\rawrxd\compilers\test_results",
    [switch]$BuildFromSource,
    [switch]$TestExecutables,
    [switch]$GenerateReport
)

# Create output directory
if (-not (Test-Path $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
}

$Report = @{
    Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    TotalLanguages = 0
    FoundLanguages = @()
    MissingLanguages = @()
    Executables = @()
    BuildResults = @()
    TestResults = @()
}

Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "Omega-Polyglot Compiler Test Suite" -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host ""

# ==============================================================================
# Test 1: Language Manifest Verification
# ==============================================================================
Write-Host "Test 1: Language Manifest Verification" -ForegroundColor Yellow
Write-Host "----------------------------------------------------------------" -ForegroundColor Yellow

$manifestPath = Join-Path $CompilerDir "languages_supported_manifest.json"
if (Test-Path $manifestPath) {
    try {
        $manifest = Get-Content $manifestPath | ConvertFrom-Json
        $Report.TotalLanguages = $manifest.totalRequested
        $Report.FoundLanguages = $manifest.found
        $Report.MissingLanguages = $manifest.missing
        
        Write-Host "  Total Requested: $($manifest.totalRequested)" -ForegroundColor White
        Write-Host "  Found: $($manifest.foundCount) languages" -ForegroundColor Green
        Write-Host "  Missing: $($manifest.missingCount) languages" -ForegroundColor Red
        Write-Host "  [PASS] Manifest loaded successfully" -ForegroundColor Green
    } catch {
        Write-Host "  [FAIL] Error parsing manifest: $_" -ForegroundColor Red
    }
} else {
    Write-Host "  [FAIL] Manifest not found at $manifestPath" -ForegroundColor Red
}
Write-Host ""

# ==============================================================================
# Test 2: Executable Testing
# ==============================================================================
if ($TestExecutables -or $GenerateReport) {
    Write-Host "Test 2: Compiler Executable Testing" -ForegroundColor Yellow
    Write-Host "----------------------------------------------------------------" -ForegroundColor Yellow
    
    $exeFiles = Get-ChildItem -Path $CompilerDir -Filter "*.exe" -File
    
    foreach ($exe in $exeFiles) {
        $exeTest = @{
            Name = $exe.Name
            Path = $exe.FullName
            Size = $exe.Length
            LastModified = $exe.LastWriteTime
            Status = "Unknown"
            Output = ""
            ExitCode = $null
        }
        
        Write-Host "  Testing: $($exe.Name)" -NoNewline
        
        try {
            # Try running with --help
            $process = Start-Process -FilePath $exe.FullName -ArgumentList "--help" `
                -RedirectStandardOutput "$OutputDir\$($exe.BaseName)_stdout.txt" `
                -RedirectStandardError "$OutputDir\$($exe.BaseName)_stderr.txt" `
                -WindowStyle Hidden -PassThru -Wait
            
            $exeTest.ExitCode = $process.ExitCode
            
            # Check output
            $stdoutFile = "$OutputDir\$($exe.BaseName)_stdout.txt"
            if (Test-Path $stdoutFile) {
                $stdout = Get-Content $stdoutFile -Raw
                $exeTest.Output = $stdout
                
                if ($stdout.Length -gt 0) {
                    $exeTest.Status = "Working"
                    Write-Host " - [WORKING]" -ForegroundColor Green
                } else {
                    $exeTest.Status = "Silent"
                    Write-Host " - [SILENT]" -ForegroundColor Yellow
                }
            } else {
                $exeTest.Status = "NoOutput"
                Write-Host " - [NO OUTPUT FILE]" -ForegroundColor Yellow
            }
        } catch {
            $exeTest.Status = "Error"
            $exeTest.Output = $_.Exception.Message
            Write-Host " - [ERROR: $_]" -ForegroundColor Red
        }
        
        $Report.Executables += $exeTest
    }
    
    $workingCount = ($Report.Executables | Where-Object { $_.Status -eq "Working" }).Count
    $silentCount = ($Report.Executables | Where-Object { $_.Status -eq "Silent" }).Count
    $errorCount = ($Report.Executables | Where-Object { $_.Status -eq "Error" }).Count
    
    Write-Host ""
    Write-Host "  Summary: $($Report.Executables.Count) executables" -ForegroundColor White
    Write-Host "    Working: $workingCount" -ForegroundColor Green
    Write-Host "    Silent: $silentCount" -ForegroundColor Yellow
    Write-Host "    Errors: $errorCount" -ForegroundColor Red
    Write-Host ""
}

# ==============================================================================
# Test 3: Assembly Source Build Test
# ==============================================================================
if ($BuildFromSource) {
    Write-Host "Test 3: Assembly Source Build Test" -ForegroundColor Yellow
    Write-Host "----------------------------------------------------------------" -ForegroundColor Yellow
    
    $ml64Path = "C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\ml64.exe"
    
    if (-not (Test-Path $ml64Path)) {
        Write-Host "  [SKIP] ml64.exe not found at $ml64Path" -ForegroundColor Yellow
    } else {
        $asmDir = Join-Path $CompilerDir "assembly_source"
        if (Test-Path $asmDir) {
            $asmFiles = Get-ChildItem -Path $asmDir -Filter "*.asm"
            
            $objDir = Join-Path $OutputDir "obj"
            New-Item -ItemType Directory -Path $objDir -Force -ErrorAction SilentlyContinue | Out-Null
            
            foreach ($asm in $asmFiles) {
                $buildResult = @{
                    SourceFile = $asm.Name
                    Status = "Unknown"
                    Log = ""
                }
                
                Write-Host "  Building: $($asm.Name)" -NoNewline
                
                $objFile = Join-Path $objDir "$($asm.BaseName).obj"
                $logFile = "$OutputDir\$($asm.BaseName)_build.log"
                
                try {
                    $process = Start-Process -FilePath $ml64Path `
                        -ArgumentList "/c", "/Fo`"$objFile`"", "/W3", "/nologo", "`"$($asm.FullName)`"" `
                        -RedirectStandardOutput $logFile `
                        -RedirectStandardError "$logFile.err" `
                        -WindowStyle Hidden -PassThru -Wait
                    
                    if ($process.ExitCode -eq 0 -and (Test-Path $objFile)) {
                        $buildResult.Status = "Success"
                        Write-Host " - [SUCCESS]" -ForegroundColor Green
                    } else {
                        $buildResult.Status = "Failed"
                        $buildResult.Log = Get-Content $logFile -Raw -ErrorAction SilentlyContinue
                        Write-Host " - [FAILED]" -ForegroundColor Red
                    }
                } catch {
                    $buildResult.Status = "Error"
                    $buildResult.Log = $_.Exception.Message
                    Write-Host " - [ERROR]" -ForegroundColor Red
                }
                
                $Report.BuildResults += $buildResult
            }
            
            $successCount = ($Report.BuildResults | Where-Object { $_.Status -eq "Success" }).Count
            $failCount = ($Report.BuildResults | Where-Object { $_.Status -eq "Failed" }).Count
            
            Write-Host ""
            Write-Host "  Build Summary: $($Report.BuildResults.Count) files" -ForegroundColor White
            Write-Host "    Success: $successCount" -ForegroundColor Green
            Write-Host "    Failed: $failCount" -ForegroundColor Red
            Write-Host ""
        } else {
            Write-Host "  [SKIP] Assembly source directory not found" -ForegroundColor Yellow
        }
    }
}

# ==============================================================================
# Generate Report
# ==============================================================================
if ($GenerateReport) {
    Write-Host "Generating Report..." -ForegroundColor Cyan
    
    $reportPath = Join-Path $OutputDir "COMPILER_TEST_REPORT.json"
    $Report | ConvertTo-Json -Depth 10 | Out-File $reportPath
    
    # Generate Markdown report
    $mdReport = @"
# Omega-Polyglot Compiler Test Report

**Generated:** $($Report.Timestamp)
**Test Directory:** $CompilerDir

## Language Support

- **Total Requested:** $($Report.TotalLanguages)
- **Found:** $($Report.FoundLanguages.Count) languages
- **Missing:** $($Report.MissingLanguages.Count) languages

### Missing Languages

| Language | Priority |
|----------|----------|
$(foreach ($lang in $Report.MissingLanguages) { "| $lang | - |`n" })

## Executable Test Results

| Name | Size | Status | Exit Code |
|------|------|--------|-----------|
$(foreach ($exe in $Report.Executables) { "| $($exe.Name) | $($exe.Size) | $($exe.Status) | $($exe.ExitCode) |`n" })

## Build Results

$(if ($Report.BuildResults.Count -gt 0) {
    "| Source File | Status |`n|-------------|--------|`n"
    foreach ($build in $Report.BuildResults) {
        "| $($build.SourceFile) | $($build.Status) |`n"
    }
} else {
    "No build tests performed. Use -BuildFromSource to test assembly compilation."
})

## Summary

- **Working Executables:** $(($Report.Executables | Where-Object { $_.Status -eq "Working" }).Count)
- **Silent Executables:** $(($Report.Executables | Where-Object { $_.Status -eq "Silent" }).Count)
- **Failed Executables:** $(($Report.Executables | Where-Object { $_.Status -eq "Error" }).Count)
- **Successful Builds:** $(($Report.BuildResults | Where-Object { $_.Status -eq "Success" }).Count)
- **Failed Builds:** $(($Report.BuildResults | Where-Object { $_.Status -eq "Failed" }).Count)

---
*Report generated by Omega-Polyglot Test Suite*
"@
    
    $mdPath = Join-Path $OutputDir "COMPILER_TEST_REPORT.md"
    $mdReport | Out-File $mdPath
    
    Write-Host "  JSON Report: $reportPath" -ForegroundColor Green
    Write-Host "  Markdown Report: $mdPath" -ForegroundColor Green
}

Write-Host ""
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "Test Complete!" -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan

# Return summary
return $Report
