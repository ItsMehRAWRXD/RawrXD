# Test JSON Control Commands for RawrXD Pipe Server
# Phase 3: Extended Protocol Demo

param(
    [string]$PipeName = "RawrXD_Inference",
    [int]$TimeoutMs = 5000
)

function Send-PipeCommand {
    param([string]$JsonCommand)
    
    $pipe = $null
    try {
        $pipe = New-Object System.IO.Pipes.NamedPipeClientStream(".", $PipeName, 
            [System.IO.Pipes.PipeDirection]::InOut, [System.IO.Pipes.PipeOptions]::None)
        $pipe.Connect($TimeoutMs)
        
        $writer = New-Object System.IO.StreamWriter($pipe)
        $writer.Write($JsonCommand)
        $writer.Flush()
        
        $reader = New-Object System.IO.StreamReader($pipe)
        $response = $reader.ReadLine()
        
        return $response
    } finally {
        if ($pipe) { $pipe.Close() }
    }
}

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "RawrXD JSON Control Commands Test" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host ""

# Test 1: Status command
Write-Host "[TEST] Status query..." -ForegroundColor Yellow
$statusCmd = '{"cmd":"status"}'
$response = Send-PipeCommand -JsonCommand $statusCmd
Write-Host "  Command: $statusCmd" -ForegroundColor Gray
Write-Host "  Response: $response" -ForegroundColor Green
Write-Host ""

# Test 2: Hotpatch command (will fail without valid model, but tests protocol)
Write-Host "[TEST] Hotpatch request..." -ForegroundColor Yellow
$hotpatchCmd = '{"cmd":"hotpatch","model_path":"D:\\temp\\test-model.gguf","gpu_layer":24}'
$response = Send-PipeCommand -JsonCommand $hotpatchCmd
Write-Host "  Command: $hotpatchCmd" -ForegroundColor Gray
Write-Host "  Response: $response" -ForegroundColor $(if ($response -like '*"status":"ok"*') { "Green" } else { "Red" })
Write-Host ""

# Test 3: Check status again (should show updated epoch)
Write-Host "[TEST] Status after hotpatch..." -ForegroundColor Yellow
$response = Send-PipeCommand -JsonCommand $statusCmd
Write-Host "  Command: $statusCmd" -ForegroundColor Gray
Write-Host "  Response: $response" -ForegroundColor Green
Write-Host ""

# Test 4: Rollback command
Write-Host "[TEST] Rollback request..." -ForegroundColor Yellow
$rollbackCmd = '{"cmd":"rollback"}'
$response = Send-PipeCommand -JsonCommand $rollbackCmd
Write-Host "  Command: $rollbackCmd" -ForegroundColor Gray
Write-Host "  Response: $response" -ForegroundColor $(if ($response -like '*"status":"ok"*') { "Green" } else { "Yellow" })
Write-Host ""

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "JSON Control Commands Test Complete" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
