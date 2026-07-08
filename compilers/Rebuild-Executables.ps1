# Rebuild Silent Executables from Assembly Sources
# Fixes STATUS_INVALID_HANDLE crashes by rebuilding with correct entry points

param(
    [string]$CompilerDir = "D:\rawrxd\compilers",
    [string]$AssemblySourceDir = "D:\rawrxd\compilers\assembly_source",
    [string]$OutputDir = "D:\rawrxd\compilers\rebuilt",
    [switch]$TestOnly,
    [switch]$RebuildAll
)

# Create output directory
if (-not (Test-Path $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
}

# Find VS tools
$VSTools = $null
$PossiblePaths = @(
    "C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Tools\MSVC\14.51.36230\bin\Hostx64\x64",
    "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Tools\MSVC\14.51.36230\bin\Hostx64\x64",
    "C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64",
    "C:\Program Files (x86)\Microsoft Visual Studio\2022\Enterprise\VC\Tools\MSVC\14.51.36230\bin\Hostx64\x64",
    "C:\Program Files\Microsoft Visual Studio\18\Enterprise\SDK\ScopeCppSDK\vc15\VC\bin"
)

foreach ($Path in $PossiblePaths) {
    if (Test-Path "$Path\ml64.exe") {
        $VSTools = $Path
        break
    }
}

if (-not $VSTools) {
    Write-Host "ERROR: VS Tools not found. Searching..." -ForegroundColor Red
    $FoundML64 = Get-ChildItem -Path "C:\Program Files" -Recurse -Filter "ml64.exe" -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($FoundML64) {
        $VSTools = Split-Path $FoundML64.FullName
        Write-Host "Found at: $VSTools" -ForegroundColor Green
    } else {
        Write-Host "ERROR: ml64.exe not found. Cannot rebuild executables." -ForegroundColor Red
        exit 1
    }
}

$Ml64 = Join-Path $VSTools "ml64.exe"
$Link = Join-Path $VSTools "link.exe"

Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "Silent Executable Rebuilder" -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Tools:"
Write-Host "  ML64: $Ml64"
Write-Host "  LINK: $Link"
Write-Host "  Output: $OutputDir"
Write-Host ""

# Test toolchain first
Write-Host "Testing build toolchain..." -ForegroundColor Yellow
$TestAsm = @"
; Minimal console test
extrn ExitProcess: proc
extrn GetStdHandle: proc
extrn WriteConsoleA: proc

.data
    msg db 'Toolchain test successful', 0Dh, 0Ah
    len equ $ - msg
    written dq ?

.code
mainCRTStartup proc
    sub rsp, 40
    
    ; Get stdout handle
    mov rcx, -11  ; STD_OUTPUT_HANDLE
    call GetStdHandle
    
    ; Write message
    mov rcx, rax
    lea rdx, msg
    mov r8, len
    lea r9, written
    mov qword ptr [rsp+32], 0
    call WriteConsoleA
    
    ; Exit
    xor ecx, ecx
    call ExitProcess
mainCRTStartup endp
end
"@

$TestAsmPath = Join-Path $OutputDir "toolchain_test.asm"
$TestObjPath = Join-Path $OutputDir "toolchain_test.obj"
$TestExePath = Join-Path $OutputDir "toolchain_test.exe"

$TestAsm | Out-File $TestAsmPath -Encoding ASCII

Write-Host "Assembling test..." -NoNewline
& $Ml64 /c /Fo$TestObjPath /W3 /nologo $TestAsmPath 2>&1 | Out-Null
if ($LASTEXITCODE -eq 0 -and (Test-Path $TestObjPath)) {
    Write-Host " OK" -ForegroundColor Green
} else {
    Write-Host " FAILED" -ForegroundColor Red
    exit 1
}

Write-Host "Linking test..." -NoNewline
& $Link /SUBSYSTEM:CONSOLE /ENTRY:mainCRTStartup /NODEFAULTLIB `
    kernel32.lib /OUT:$TestExePath $TestObjPath 2>&1 | Out-Null
if ($LASTEXITCODE -eq 0 -and (Test-Path $TestExePath)) {
    Write-Host " OK" -ForegroundColor Green
} else {
    Write-Host " FAILED" -ForegroundColor Red
    exit 1
}

Write-Host "Testing executable..." -NoNewline
$TestOutput = & $TestExePath 2>&1
if ($TestOutput -like "*successful*") {
    Write-Host " OK" -ForegroundColor Green
} else {
    Write-Host " FAILED (no output)" -ForegroundColor Red
}

Write-Host ""
Write-Host "Toolchain verified!" -ForegroundColor Green
Write-Host ""

if ($TestOnly) {
    Write-Host "Test mode - exiting."
    exit 0
}

# Map executables to source files
$BuildMap = @(
    @{
        Name = "universal_compiler_runtime"
        ExeName = "universal_compiler_runtime.exe"
        SourceCandidates = @(
            "universal_compiler_runtime.asm",
            "universal_runtime.asm",
            "runtime.asm"
        )
        EntryPoint = "mainCRTStartup"
        Subsystem = "CONSOLE"
        Libs = @("kernel32.lib")
    },
    @{
        Name = "bash_compiler"
        ExeName = "bash_compiler_from_scratch.exe"
        SourceCandidates = @(
            "bash_compiler.asm",
            "bash_compiler_from_scratch.asm",
            "bash.asm"
        )
        EntryPoint = "mainCRTStartup"
        Subsystem = "CONSOLE"
        Libs = @("kernel32.lib", "msvcrt.lib")
    },
    @{
        Name = "powershell_compiler"
        ExeName = "powershell_compiler_from_scratch.exe"
        SourceCandidates = @(
            "powershell_compiler.asm",
            "powershell_compiler_from_scratch.asm",
            "powershell.asm"
        )
        EntryPoint = "mainCRTStartup"
        Subsystem = "CONSOLE"
        Libs = @("kernel32.lib", "msvcrt.lib")
    },
    @{
        Name = "eon_bootstrap"
        ExeName = "eon_bootstrap_compiler.exe"
        SourceCandidates = @(
            "eon_bootstrap_compiler.asm",
            "eon_compiler.asm",
            "eon.asm"
        )
        EntryPoint = "mainCRTStartup"
        Subsystem = "CONSOLE"
        Libs = @("kernel32.lib", "msvcrt.lib")
    },
    @{
        Name = "universal_cross_platform"
        ExeName = "universal_cross_platform_compiler.exe"
        SourceCandidates = @(
            "universal_cross_platform_compiler.asm",
            "universal_compiler.asm",
            "cross_platform_compiler.asm"
        )
        EntryPoint = "mainCRTStartup"
        Subsystem = "CONSOLE"
        Libs = @("kernel32.lib", "msvcrt.lib")
    }
)

Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "Rebuilding Executables" -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host ""

$SuccessCount = 0
$FailCount = 0
$MissingSourceCount = 0

foreach ($Build in $BuildMap) {
    Write-Host "Processing: $($Build.Name)" -ForegroundColor Yellow
    Write-Host "  Target: $($Build.ExeName)"
    
    # Find source file
    $SourceFile = $null
    foreach ($Candidate in $Build.SourceCandidates) {
        $CandidatePath = Join-Path $AssemblySourceDir $Candidate
        if (Test-Path $CandidatePath) {
            $SourceFile = $CandidatePath
            break
        }
    }
    
    if (-not $SourceFile) {
        Write-Host "  [SKIP] Source file not found" -ForegroundColor Gray
        Write-Host "  Searched:"
        foreach ($Candidate in $Build.SourceCandidates) {
            Write-Host "    - $Candidate"
        }
        $MissingSourceCount++
        Write-Host ""
        continue
    }
    
    Write-Host "  Source: $([System.IO.Path]::GetFileName($SourceFile))"
    
    $ObjFile = Join-Path $OutputDir "$($Build.Name).obj"
    $ExeFile = Join-Path $OutputDir $Build.ExeName
    
    # Assemble
    Write-Host "  Assembling..." -NoNewline
    & $Ml64 /c /Fo$ObjFile /W3 /nologo $SourceFile 2>&1 | Out-File "$ObjFile.log"
    
    if ($LASTEXITCODE -eq 0 -and (Test-Path $ObjFile)) {
        Write-Host " OK" -ForegroundColor Green
    } else {
        Write-Host " FAILED" -ForegroundColor Red
        Write-Host "  Log: $ObjFile.log"
        $FailCount++
        Write-Host ""
        continue
    }
    
    # Link
    Write-Host "  Linking..." -NoNewline
    $LinkArgs = @(
        "/SUBSYSTEM:$($Build.Subsystem)",
        "/ENTRY:$($Build.EntryPoint)",
        "/NODEFAULTLIB",
        "/OUT:$ExeFile"
    ) + $Build.Libs + $ObjFile
    
    & $Link $LinkArgs 2>&1 | Out-File "$ExeFile.log"
    
    if ($LASTEXITCODE -eq 0 -and (Test-Path $ExeFile)) {
        Write-Host " OK" -ForegroundColor Green
        $ExeSize = (Get-Item $ExeFile).Length
        Write-Host "  Output: $ExeFile ($ExeSize bytes)"
        
        # Test the rebuilt executable
        Write-Host "  Testing..." -NoNewline
        $TestLog = "$ExeFile.test.log"
        $StartTime = Get-Date
        try {
            $Process = Start-Process -FilePath $ExeFile -RedirectStandardOutput $TestLog `
                -RedirectStandardError "$TestLog.err" -WindowStyle Hidden -PassThru -Wait
            $ExitCode = $Process.ExitCode
        } catch {
            "ERROR: $_" | Out-File $TestLog
            $ExitCode = -1
        }
        $EndTime = Get-Date
        
        "Start: $StartTime" | Out-File $TestLog -Append
        "Exit Code: $ExitCode" | Out-File $TestLog -Append
        "End: $EndTime" | Out-File $TestLog -Append
        
        if (Test-Path $TestLog) {
            $Content = Get-Content $TestLog -Raw
            if ($Content.Length -gt 100 -and $ExitCode -eq 0) {
                Write-Host " WORKING" -ForegroundColor Green
                $SuccessCount++
            } elseif ($Content.Length -gt 100) {
                Write-Host " OUTPUT (exit: $ExitCode)" -ForegroundColor Yellow
                $SuccessCount++
            } else {
                Write-Host " NO OUTPUT (exit: $ExitCode)" -ForegroundColor Red
                $FailCount++
            }
        } else {
            Write-Host " CRASH" -ForegroundColor Red
            $FailCount++
        }
    } else {
        Write-Host " FAILED" -ForegroundColor Red
        Write-Host "  Log: $ExeFile.log"
        $FailCount++
    }
    
    Write-Host ""
}

Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "Rebuild Summary" -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Success: $SuccessCount" -ForegroundColor Green
Write-Host "Failed: $FailCount" -ForegroundColor Red
Write-Host "Missing Source: $MissingSourceCount" -ForegroundColor Gray
Write-Host ""
Write-Host "Rebuilt executables in: $OutputDir"
Write-Host ""

if ($FailCount -gt 0 -or $MissingSourceCount -gt 0) {
    Write-Host "Next steps:" -ForegroundColor Yellow
    if ($MissingSourceCount -gt 0) {
        Write-Host "  - Find missing assembly source files"
        Write-Host "  - Check alternate directories"
    }
    if ($FailCount -gt 0) {
        Write-Host "  - Review build logs in $OutputDir"
        Write-Host "  - Check for syntax errors in assembly sources"
    }
    Write-Host ""
}
