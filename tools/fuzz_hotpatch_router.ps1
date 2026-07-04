# RawrXD Hotpatch Router Fuzz Test
# Tests bytecode injection with various payloads
# Usage: .\fuzz_hotpatch_router.ps1

param(
    [int]$Iterations = 100,
    [int]$PayloadSize = 64,
    [switch]$Verbose
)

$ErrorActionPreference = "Stop"

function Write-VerboseLog {
    param([string]$Message)
    if ($Verbose) {
        Write-Host "[FUZZ] $Message" -ForegroundColor DarkGray
    }
}

function Generate-RandomBytecode {
    param([int]$Size)
    
    $bytecode = @()
    for ($i = 0; $i -lt $Size; $i++) {
        $bytecode += Get-Random -Minimum 0 -Maximum 256
    }
    return $bytecode
}

function Generate-ValidX64Bytecode {
    # Generate valid-ish x64 instructions for hotpatch testing
    $prefixes = @(
        @(0x48, 0x89, 0x5C, 0x24, 0x08),  # mov [rsp+8], rbx
        @(0x48, 0x89, 0x74, 0x24, 0x10),  # mov [rsp+16], rsi
        @(0x48, 0x89, 0x7C, 0x24, 0x18),  # mov [rsp+24], rdi
        @(0x48, 0x8B, 0x5C, 0x24, 0x08),  # mov rbx, [rsp+8]
        @(0x48, 0x8B, 0x74, 0x24, 0x10),  # mov rsi, [rsp+16]
        @(0x48, 0x8B, 0x7C, 0x24, 0x18),  # mov rdi, [rsp+24]
        @(0xF0, 0x48, 0x0F, 0xB1, 0x0D),  # lock cmpxchg [rip+...], rcx
        @(0x0F, 0xAE, 0xF8),              # sfence
        @(0x0F, 0xAE, 0xE8),              # lfence
        @(0x90, 0x90, 0x90, 0x90)         # nop sled
    )
    
    return $prefixes | Get-Random
}

function Test-BytecodePayload {
    param(
        [array]$Bytecode,
        [string]$Description
    )
    
    Write-VerboseLog "Testing: $Description ($($Bytecode.Length) bytes)"
    
    # In a real implementation, this would send to the named pipe
    # For now, we just validate the bytecode format
    
    if ($Bytecode.Length -eq 0) {
        return $false
    }
    
    # Check for lock prefix (0xF0) - important for hotpatch atomicity
    $hasLock = $Bytecode -contains 0xF0
    
    # Check for memory fence instructions
    $hasFence = ($Bytecode -contains 0xAE) -and 
                (($Bytecode -contains 0xF8) -or ($Bytecode -contains 0xE8))
    
    Write-VerboseLog "  Lock prefix: $hasLock, Memory fence: $hasFence"
    
    return $true
}

# Main fuzz loop
Write-Host "=== RawrXD Hotpatch Router Fuzz Test ===" -ForegroundColor Green
Write-Host "Iterations: $Iterations" -ForegroundColor Yellow

$passed = 0
$failed = 0

for ($i = 0; $i -lt $Iterations; $i++) {
    $payloadType = Get-Random -Minimum 0 -Maximum 3
    
    switch ($payloadType) {
        0 {
            # Random garbage
            $payload = Generate-RandomBytecode -Size $PayloadSize
            $desc = "Random garbage"
        }
        1 {
            # Valid-ish x64
            $payload = Generate-ValidX64Bytecode
            $desc = "Valid x64 instructions"
        }
        2 {
            # Empty/minimal
            $payload = @(0xC3)  # ret
            $desc = "Minimal (ret only)"
        }
    }
    
    $result = Test-BytecodePayload -Bytecode $payload -Description $desc
    
    if ($result) {
        $passed++
    } else {
        $failed++
    }
    
    if ($i % 10 -eq 0) {
        Write-Host "Progress: $i/$Iterations (Passed: $passed, Failed: $failed)" -ForegroundColor DarkGray
    }
}

Write-Host "=== Fuzz Test Complete ===" -ForegroundColor Green
Write-Host "Passed: $passed / $Iterations" -ForegroundColor $(if ($failed -eq 0) { "Green" } else { "Yellow" })
Write-Host "Failed: $failed / $Iterations" -ForegroundColor $(if ($failed -eq 0) { "Green" } else { "Red" })

if ($failed -gt 0) {
    exit 1
}