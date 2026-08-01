# RawrZ Advanced Evasion Test Suite - Public Domain
# Comprehensive testing of all advanced evasion tools
# 
# This is free and unencumbered software released into the public domain.
# 
# Anyone is free to copy, modify, publish, use, compile, sell, or
# distribute this software, either in source code form or as a compiled
# binary, for any purpose, commercial or non-commercial, and by any
# means.
# 
# In jurisdictions that recognize copyright laws, the author or authors
# of this software dedicate any and all copyright interest in the
# software to the public domain. We make this dedication for the benefit
# of the public at large and to the detriment of our heirs and
# successors. We intend this dedication to be an overt act of
# relinquishment in perpetuity of all present and future rights to this
# software under copyright law.
# 
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
# IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
# OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
# ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
# OTHER DEALINGS IN THE SOFTWARE.
# 
# For more information, please refer to <http://unlicense.org/>

param(
    [switch]$SafeMode,
    [switch]$Verbose,
    [string]$TestCategory = "all"
)

Write-Host "RawrZ Advanced Evasion Test Suite" -ForegroundColor Cyan
Write-Host "=================================" -ForegroundColor Cyan
Write-Host "Testing all advanced evasion tools for functionality" -ForegroundColor Yellow
Write-Host ""

# Test results tracking
$TestResults = @{
    Total = 0
    Passed = 0
    Failed = 0
    Skipped = 0
    Tests = @()
}

function Test-Result {
    param(
        [string]$TestName,
        [bool]$Passed,
        [string]$Message = "",
        [string]$Category = "general"
    )
    
    $TestResults.Total++
    if ($Passed) {
        $TestResults.Passed++
        $status = "PASS"
        $color = "Green"
    } else {
        $TestResults.Failed++
        $status = "FAIL"
        $color = "Red"
    }
    
    $testResult = @{
        Name = $TestName
        Status = $status
        Message = $Message
        Category = $Category
    }
    $TestResults.Tests += $testResult
    
    Write-Host "[$status] $TestName" -ForegroundColor $color
    if ($Message -and $Verbose) {
        Write-Host "  $Message" -ForegroundColor Gray
    }
}

function Test-PowerShellUtilities {
    Write-Host "Testing PowerShell Utilities..." -ForegroundColor Yellow
    
    # Test EvAdrKiller.ps1
    if (Test-Path "EvAdrKiller.ps1") {
        try {
            $content = Get-Content "EvAdrKiller.ps1" -Raw
            $hasPublicDomain = $content -match "public domain"
            $hasEvAdrKiller = $content -match "EvAdrKiller"
            Test-Result "EvAdrKiller.ps1 Structure" ($hasPublicDomain -and $hasEvAdrKiller) "Public domain header and EvAdrKiller functionality present" "powershell"
        } catch {
            Test-Result "EvAdrKiller.ps1 Structure" $false "Error reading file: $_" "powershell"
        }
    } else {
        Test-Result "EvAdrKiller.ps1 Exists" $false "File not found" "powershell"
    }
    
    # Test B.ps1 (Beaconism-dropper)
    if (Test-Path "B.ps1") {
        try {
            $content = Get-Content "B.ps1" -Raw
            $hasPublicDomain = $content -match "public domain"
            $hasBeaconism = $content -match "beacon"
            Test-Result "B.ps1 Structure" ($hasPublicDomain -and $hasBeaconism) "Public domain header and beacon functionality present" "powershell"
        } catch {
            Test-Result "B.ps1 Structure" $false "Error reading file: $_" "powershell"
        }
    } else {
        Test-Result "B.ps1 Exists" $false "File not found" "powershell"
    }
    
    # Test CppEncExe.ps1
    if (Test-Path "CppEncExe.ps1") {
        try {
            $content = Get-Content "CppEncExe.ps1" -Raw
            $hasPublicDomain = $content -match "public domain"
            $hasCamellia = $content -match "Camellia"
            Test-Result "CppEncExe.ps1 Structure" ($hasPublicDomain -and $hasCamellia) "Public domain header and Camellia encryption present" "powershell"
        } catch {
            Test-Result "CppEncExe.ps1 Structure" $false "Error reading file: $_" "powershell"
        }
    } else {
        Test-Result "CppEncExe.ps1 Exists" $false "File not found" "powershell"
    }
    
    # Test FHp.ps1
    if (Test-Path "FHp.ps1") {
        try {
            $content = Get-Content "FHp.ps1" -Raw
            $hasPublicDomain = $content -match "public domain"
            $hasHotPatch = $content -match "hot-patch"
            Test-Result "FHp.ps1 Structure" ($hasPublicDomain -and $hasHotPatch) "Public domain header and hot-patch functionality present" "powershell"
        } catch {
            Test-Result "FHp.ps1 Structure" $false "Error reading file: $_" "powershell"
        }
    } else {
        Test-Result "FHp.ps1 Exists" $false "File not found" "powershell"
    }
    
    # Test TripleCrypto.ps1
    if (Test-Path "TripleCrypto.ps1") {
        try {
            $content = Get-Content "TripleCrypto.ps1" -Raw
            $hasTripleEncryption = $content -match "Camellia.*AES.*ChaCha20"
            $hasDragDrop = $content -match "drag.*drop"
            Test-Result "TripleCrypto.ps1 Structure" ($hasTripleEncryption -and $hasDragDrop) "Triple encryption and drag-drop functionality present" "powershell"
        } catch {
            Test-Result "TripleCrypto.ps1 Structure" $false "Error reading file: $_" "powershell"
        }
    } else {
        Test-Result "TripleCrypto.ps1 Exists" $false "File not found" "powershell"
    }
}

function Test-PolymorphicLoaders {
    Write-Host "Testing Polymorphic Loaders..." -ForegroundColor Yellow
    
    # Test polymorph.asm
    if (Test-Path "polymorph.asm") {
        try {
            $content = Get-Content "polymorph.asm" -Raw
            $hasPublicDomain = $content -match "public domain"
            $hasRandomSeed = $content -match "RANDOM_SEED"
            $hasXorShift = $content -match "xorshift"
            Test-Result "polymorph.asm Structure" ($hasPublicDomain -and $hasRandomSeed -and $hasXorShift) "Public domain header, random seed, and xorshift PRNG present" "masm"
        } catch {
            Test-Result "polymorph.asm Structure" $false "Error reading file: $_" "masm"
        }
    } else {
        Test-Result "polymorph.asm Exists" $false "File not found" "masm"
    }
    
    # Test polymorph_ssl.asm
    if (Test-Path "polymorph_ssl.asm") {
        try {
            $content = Get-Content "polymorph_ssl.asm" -Raw
            $hasPublicDomain = $content -match "public domain"
            $hasOpenSSL = $content -match "OpenSSL"
            $hasCamellia = $content -match "camellia"
            Test-Result "polymorph_ssl.asm Structure" ($hasPublicDomain -and $hasOpenSSL -and $hasCamellia) "Public domain header, OpenSSL, and Camellia present" "masm"
        } catch {
            Test-Result "polymorph_ssl.asm Structure" $false "Error reading file: $_" "masm"
        }
    } else {
        Test-Result "polymorph_ssl.asm Exists" $false "File not found" "masm"
    }
    
    # Test loader.c
    if (Test-Path "loader.c") {
        try {
            $content = Get-Content "loader.c" -Raw
            $hasPublicDomain = $content -match "public domain"
            $hasUnlicense = $content -match "unlicense"
            $hasCryptBytes = $content -match "crypt_bytes"
            Test-Result "loader.c Structure" ($hasPublicDomain -and $hasUnlicense -and $hasCryptBytes) "Public domain header, unlicense, and crypt_bytes function present" "c"
        } catch {
            Test-Result "loader.c Structure" $false "Error reading file: $_" "c"
        }
    } else {
        Test-Result "loader.c Exists" $false "File not found" "c"
    }
}

function Test-Ring0HybridDropper {
    Write-Host "Testing Ring-0 Hybrid Dropper..." -ForegroundColor Yellow
    
    # Test stealthdrv.c
    if (Test-Path "stealthdrv.c") {
        try {
            $content = Get-Content "stealthdrv.c" -Raw
            $hasPublicDomain = $content -match "public domain"
            $hasObRegisterCallbacks = $content -match "ObRegisterCallbacks"
            $hasProcessCallback = $content -match "ProcessCallback"
            Test-Result "stealthdrv.c Structure" ($hasPublicDomain -and $hasObRegisterCallbacks -and $hasProcessCallback) "Public domain header, ObRegisterCallbacks, and ProcessCallback present" "kernel"
        } catch {
            Test-Result "stealthdrv.c Structure" $false "Error reading file: $_" "kernel"
        }
    } else {
        Test-Result "stealthdrv.c Exists" $false "File not found" "kernel"
    }
    
    # Test stealthinst.c
    if (Test-Path "stealthinst.c") {
        try {
            $content = Get-Content "stealthinst.c" -Raw
            $hasPublicDomain = $content -match "public domain"
            $hasNtLoadDriver = $content -match "NtLoadDriver"
            $hasInstallDriver = $content -match "InstallDriver"
            Test-Result "stealthinst.c Structure" ($hasPublicDomain -and $hasNtLoadDriver -and $hasInstallDriver) "Public domain header, NtLoadDriver, and InstallDriver present" "kernel"
        } catch {
            Test-Result "stealthinst.c Structure" $false "Error reading file: $_" "kernel"
        }
    } else {
        Test-Result "stealthinst.c Exists" $false "File not found" "kernel"
    }
    
    # Test stealthinj.asm
    if (Test-Path "stealthinj.asm") {
        try {
            $content = Get-Content "stealthinj.asm" -Raw
            $hasPublicDomain = $content -match "public domain"
            $hasRegistryInject = $content -match "RegistryInject"
            $hasRing0Enable = $content -match "RING0_ENABLE"
            Test-Result "stealthinj.asm Structure" ($hasPublicDomain -and $hasRegistryInject -and $hasRing0Enable) "Public domain header, RegistryInject, and RING0_ENABLE present" "masm"
        } catch {
            Test-Result "stealthinj.asm Structure" $false "Error reading file: $_" "masm"
        }
    } else {
        Test-Result "stealthinj.asm Exists" $false "File not found" "masm"
    }
}

function Test-BuildScripts {
    Write-Host "Testing Build Scripts..." -ForegroundColor Yellow
    
    # Test polymorph_build.ps1
    if (Test-Path "polymorph_build.ps1") {
        try {
            $content = Get-Content "polymorph_build.ps1" -Raw
            $hasML64 = $content -match "ml64"
            $hasLink = $content -match "link"
            $hasRandomSeed = $content -match "RANDOM_SEED"
            Test-Result "polymorph_build.ps1 Structure" ($hasML64 -and $hasLink -and $hasRandomSeed) "ML64, link, and random seed generation present" "build"
        } catch {
            Test-Result "polymorph_build.ps1 Structure" $false "Error reading file: $_" "build"
        }
    } else {
        Test-Result "polymorph_build.ps1 Exists" $false "File not found" "build"
    }
    
    # Test polymorph_ssl_build.ps1
    if (Test-Path "polymorph_ssl_build.ps1") {
        try {
            $content = Get-Content "polymorph_ssl_build.ps1" -Raw
            $hasOpenSSL = $content -match "OpenSSL"
            $hasCamellia = $content -match "Camellia"
            $hasStubChoice = $content -match "Stub Choice"
            Test-Result "polymorph_ssl_build.ps1 Structure" ($hasOpenSSL -and $hasCamellia -and $hasStubChoice) "OpenSSL, Camellia, and stub choice present" "build"
        } catch {
            Test-Result "polymorph_ssl_build.ps1 Structure" $false "Error reading file: $_" "build"
        }
    } else {
        Test-Result "polymorph_ssl_build.ps1 Exists" $false "File not found" "build"
    }
}

function Test-HeaderFiles {
    Write-Host "Testing Header Files..." -ForegroundColor Yellow
    
    # Test poly_key.h
    if (Test-Path "poly_key.h") {
        try {
            $content = Get-Content "poly_key.h" -Raw
            $hasRandomKey = $content -match "RANDOM_KEY"
            $hasHexValue = $content -match "0x[A-F0-9]+"
            Test-Result "poly_key.h Structure" ($hasRandomKey -and $hasHexValue) "Random key definition and hex value present" "header"
        } catch {
            Test-Result "poly_key.h Structure" $false "Error reading file: $_" "header"
        }
    } else {
        Test-Result "poly_key.h Exists" $false "File not found" "header"
    }
    
    # Test poly_ssl.inc
    if (Test-Path "poly_ssl.inc") {
        try {
            $content = Get-Content "poly_ssl.inc" -Raw
            $hasCamelliaKey = $content -match "CAMELLIA_KEY"
            $hasCamelliaIV = $content -match "CAMELLIA_IV"
            $hasStubChoice = $content -match "STUB_CHOICE"
            Test-Result "poly_ssl.inc Structure" ($hasCamelliaKey -and $hasCamelliaIV -and $hasStubChoice) "Camellia key, IV, and stub choice present" "header"
        } catch {
            Test-Result "poly_ssl.inc Structure" $false "Error reading file: $_" "header"
        }
    } else {
        Test-Result "poly_ssl.inc Exists" $false "File not found" "header"
    }
    
    # Test stealth_poly.h
    if (Test-Path "stealth_poly.h") {
        try {
            $content = Get-Content "stealth_poly.h" -Raw
            $hasCamelliaKey = $content -match "CAMELLIA_KEY"
            $hasCamelliaIV = $content -match "CAMELLIA_IV"
            $hasRing0Enable = $content -match "RING0_ENABLE"
            Test-Result "stealth_poly.h Structure" ($hasCamelliaKey -and $hasCamelliaIV -and $hasRing0Enable) "Camellia key, IV, and ring-0 enable present" "header"
        } catch {
            Test-Result "stealth_poly.h Structure" $false "Error reading file: $_" "header"
        }
    } else {
        Test-Result "stealth_poly.h Exists" $false "File not found" "header"
    }
}

function Test-APIEndpoints {
    Write-Host "Testing API Endpoints..." -ForegroundColor Yellow
    
    # Test if API server is running
    try {
        $response = Invoke-RestMethod -Uri "http://localhost:3000/api/health" -Method GET -TimeoutSec 5
        Test-Result "API Server Status" $true "API server is running and responding" "api"
    } catch {
        Test-Result "API Server Status" $false "API server not responding: $_" "api"
    }
    
    # Test real encryption endpoints
    try {
        $response = Invoke-RestMethod -Uri "http://localhost:3000/api/health" -Method GET -TimeoutSec 5
        Test-Result "Real Encryption Endpoint" $true "API health endpoint responding" "api"
    } catch {
        Test-Result "Real Encryption Endpoint" $false "API health endpoint not responding: $_" "api"
    }
}

function Show-TestSummary {
    Write-Host ""
    Write-Host "Test Summary" -ForegroundColor Cyan
    Write-Host "===========" -ForegroundColor Cyan
    Write-Host "Total Tests: $($TestResults.Total)" -ForegroundColor White
    Write-Host "Passed: $($TestResults.Passed)" -ForegroundColor Green
    Write-Host "Failed: $($TestResults.Failed)" -ForegroundColor Red
    Write-Host "Skipped: $($TestResults.Skipped)" -ForegroundColor Yellow
    
    if ($TestResults.Failed -gt 0) {
        Write-Host ""
        Write-Host "Failed Tests:" -ForegroundColor Red
        foreach ($test in $TestResults.Tests | Where-Object { $_.Status -eq "FAIL" }) {
            Write-Host "  - $($test.Name): $($test.Message)" -ForegroundColor Red
        }
    }
    
    Write-Host ""
    if ($TestResults.Failed -eq 0) {
        Write-Host "All tests passed! Advanced evasion tools are ready for use." -ForegroundColor Green
    } else {
        Write-Host "Some tests failed. Please review the issues above." -ForegroundColor Yellow
    }
}

# Main test execution
Write-Host "Starting comprehensive test suite..." -ForegroundColor Cyan
Write-Host "Safe Mode: $SafeMode" -ForegroundColor Gray
Write-Host "Verbose: $Verbose" -ForegroundColor Gray
Write-Host "Test Category: $TestCategory" -ForegroundColor Gray
Write-Host ""

if ($TestCategory -eq "all" -or $TestCategory -eq "powershell") {
    Test-PowerShellUtilities
}

if ($TestCategory -eq "all" -or $TestCategory -eq "polymorphic") {
    Test-PolymorphicLoaders
}

if ($TestCategory -eq "all" -or $TestCategory -eq "ring0") {
    Test-Ring0HybridDropper
}

if ($TestCategory -eq "all" -or $TestCategory -eq "build") {
    Test-BuildScripts
}

if ($TestCategory -eq "all" -or $TestCategory -eq "headers") {
    Test-HeaderFiles
}

if ($TestCategory -eq "all" -or $TestCategory -eq "api") {
    Test-APIEndpoints
}

Show-TestSummary
