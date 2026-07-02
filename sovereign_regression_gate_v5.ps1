# ==============================================================================
# Sovereign Regression Gate v5 ? Fail-Fast, Non-Blocking Aware
# ==============================================================================
param(
    [int]$RequestCount = 100,
    [int]$CancelPercent = 15,
    [int]$Seed = 42,
    [int]$Streamer = -1,
    [string]$ExePath = "d:\rawrxd-ci-bootstrap\SovereignOrchestrator.exe",
    [string]$ModelPath = "F:\OllamaModels\Phi-3-mini-4k-instruct-q8_0.gguf",
    [int]$ResponseTimeoutMs = 5000,
    [int]$InferenceTimeoutMs = 30000,
    [switch]$AttachExisting,
    [switch]$Verbose
)

$ErrorActionPreference = "Stop"

Add-Type @"
using System;
using System.Runtime.InteropServices;
public static class NativeMethods {
    [DllImport("kernel32.dll", SetLastError=true)] public static extern IntPtr OpenEventA(uint dwDesiredAccess, bool bInheritHandle, string lpName);
    [DllImport("kernel32.dll", SetLastError=true)] public static extern IntPtr OpenFileMappingA(uint dwDesiredAccess, bool bInheritHandle, string lpName);
    [DllImport("kernel32.dll", SetLastError=true)] public static extern IntPtr MapViewOfFile(IntPtr hFileMappingObject, uint dwDesiredAccess, uint dwFileOffsetHigh, uint dwFileOffsetLow, UIntPtr dwNumberOfBytesToMap);
    [DllImport("kernel32.dll", SetLastError=true)] public static extern bool UnmapViewOfFile(IntPtr lpBaseAddress);
    [DllImport("kernel32.dll", SetLastError=true)] public static extern bool CloseHandle(IntPtr hObject);
    [DllImport("kernel32.dll", SetLastError=true)] public static extern bool SetEvent(IntPtr hEvent);
    [DllImport("kernel32.dll", SetLastError=true)] public static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);
    public const uint EVENT_MODIFY_STATE = 0x0002;
    public const uint SYNCHRONIZE = 0x00100000;
    public const uint FILE_MAP_ALL_ACCESS = 0xF001F;
    public const uint WAIT_OBJECT_0 = 0;
}
"@

$OFF_STATE=0x00; $OFF_CMD_TYPE=0x08; $OFF_PAYLOAD_LEN=0x0C; $OFF_RESP_STATUS=0x10; $OFF_RESP_LEN=0x14
$OFF_CMD_PAYLOAD=0x18; $OFF_RESP_PAYLOAD=0x1018; $OFF_TELEM_TOKENS=0x2020; $OFF_MODEL_STATE=0x2030; $OFF_MAGIC_COOKIE=0xFFF0
$BEACON_READY=0x01; $CMD_GET_STATUS=0x1002; $CMD_SHUTDOWN=0x1003; $CMD_LOAD_MODEL=0x2000; $CMD_INFER=0x3003; $CMD_CANCEL_INFER=0x3005
$CMD_STREAM_START=0x4000; $CMD_STREAM_STOP=0x4001; $CMD_STREAM_STATUS=0x4004
$RESP_OK=0; $RESP_BUSY=7; $RESP_CANCELLED=8
$RESP_NOT_READY=5
$MODEL_STATE_READY=2
$MAGIC_COOKIE=[Convert]::ToUInt64("CAFEBABEDEADBEEF",16)

function Read-U32([IntPtr]$b,[int]$o){$x=New-Object byte[] 4;[Runtime.InteropServices.Marshal]::Copy([IntPtr]::Add($b,$o),$x,0,4);[BitConverter]::ToUInt32($x,0)}
function Read-U64([IntPtr]$b,[int]$o){$x=New-Object byte[] 8;[Runtime.InteropServices.Marshal]::Copy([IntPtr]::Add($b,$o),$x,0,8);[BitConverter]::ToUInt64($x,0)}
function Write-U32([IntPtr]$b,[int]$o,[uint32]$v){$x=[BitConverter]::GetBytes($v);[Runtime.InteropServices.Marshal]::Copy($x,0,[IntPtr]::Add($b,$o),4)}
function Write-Bytes([IntPtr]$b,[int]$o,[byte[]]$v){[Runtime.InteropServices.Marshal]::Copy($v,0,[IntPtr]::Add($b,$o),$v.Length)}
function Wait-OrchReady([IntPtr]$b,[int]$t){$sw=[Diagnostics.Stopwatch]::StartNew();while($sw.ElapsedMilliseconds -lt $t){if((Read-U64 $b $OFF_MAGIC_COOKIE)-eq $MAGIC_COOKIE){return $true};Start-Sleep -Milliseconds 50};$false}

function Send-Command([IntPtr]$b,[IntPtr]$hCmd,[IntPtr]$hResp,[uint32]$cmd,[byte[]]$payload,[int]$timeout){
    Write-U32 $b $OFF_CMD_TYPE $cmd
    if($payload){Write-U32 $b $OFF_PAYLOAD_LEN $payload.Length;Write-Bytes $b $OFF_CMD_PAYLOAD $payload}else{Write-U32 $b $OFF_PAYLOAD_LEN 0}
    Write-U32 $b $OFF_STATE $BEACON_READY
    [void][NativeMethods]::SetEvent($hCmd)
    $w=[NativeMethods]::WaitForSingleObject($hResp,[uint32]$timeout)
    if($w -ne [NativeMethods]::WAIT_OBJECT_0){ return @{Success=$false;Error='RESP_TIMEOUT'} }
    @{Success=$true;Status=(Read-U32 $b $OFF_RESP_STATUS);Len=(Read-U32 $b $OFF_RESP_LEN)}
}

function Wait-InferenceComplete([IntPtr]$b,[int]$timeout){
    $sw=[Diagnostics.Stopwatch]::StartNew();$last=-1; $lastSampleMs = -1000
    while($sw.ElapsedMilliseconds -lt $timeout){
        $s=Read-U32 $b $OFF_MODEL_STATE
        if($s -eq $MODEL_STATE_READY){ return @{Success=$true;Ms=$sw.ElapsedMilliseconds;State=$s} }
        if($Verbose -and $s -ne $last){ Write-Host ("      state {0}->{1}" -f $last,$s) -ForegroundColor DarkGray; $last=$s }
        if($Verbose -and (($sw.ElapsedMilliseconds - $lastSampleMs) -ge 1000)){
            $tok = Read-U64 $b $OFF_TELEM_TOKENS
            Write-Host ("      wait={0}ms state={1} tokens={2}" -f $sw.ElapsedMilliseconds, $s, $tok) -ForegroundColor DarkGray
            $lastSampleMs = $sw.ElapsedMilliseconds
        }
        if($sw.ElapsedMilliseconds -lt 100){Start-Sleep -Milliseconds 1}elseif($sw.ElapsedMilliseconds -lt 1000){Start-Sleep -Milliseconds 5}else{Start-Sleep -Milliseconds 10}
    }
    @{Success=$false;Ms=$sw.ElapsedMilliseconds;State=(Read-U32 $b $OFF_MODEL_STATE)}
}

$proc=$null;$hMap=[IntPtr]::Zero;$pMap=[IntPtr]::Zero;$hCmd=[IntPtr]::Zero;$hResp=[IntPtr]::Zero;$hCancel=[IntPtr]::Zero
function Cleanup-All{
    try{if($pMap -ne [IntPtr]::Zero -and $hCmd -ne [IntPtr]::Zero -and $hResp -ne [IntPtr]::Zero){[void](Send-Command $pMap $hCmd $hResp $CMD_SHUTDOWN $null 3000)}}catch{}
    if($hCancel -ne [IntPtr]::Zero){[void][NativeMethods]::CloseHandle($hCancel)}
    if($hResp -ne [IntPtr]::Zero){[void][NativeMethods]::CloseHandle($hResp)}
    if($hCmd -ne [IntPtr]::Zero){[void][NativeMethods]::CloseHandle($hCmd)}
    if($pMap -ne [IntPtr]::Zero){[void][NativeMethods]::UnmapViewOfFile($pMap)}
    if($hMap -ne [IntPtr]::Zero){[void][NativeMethods]::CloseHandle($hMap)}
    if($proc -and -not $proc.HasExited){try{$proc|Stop-Process -Force -ErrorAction SilentlyContinue}catch{}}
}

try{
    if(-not (Test-Path $ExePath)){ throw "Missing exe: $ExePath" }
    if(-not (Test-Path $ModelPath)){ throw "Missing model: $ModelPath" }

    Write-Host "================================================================" -ForegroundColor Cyan
    Write-Host "Sovereign Regression Gate v5" -ForegroundColor Cyan
    Write-Host "================================================================" -ForegroundColor Cyan
    Write-Host "Requests=$RequestCount Cancel%=$CancelPercent Seed=$Seed Streamer=$Streamer"

    if(-not $AttachExisting){
        Get-Process | ? { $_.ProcessName -like '*SovereignOrchestrator*' } | Stop-Process -Force -ErrorAction SilentlyContinue
        Start-Sleep -Milliseconds 500

        $proc=Start-Process -FilePath $ExePath -PassThru -WindowStyle Hidden
    }

    $sw=[Diagnostics.Stopwatch]::StartNew()
    while($sw.ElapsedMilliseconds -lt 10000 -and $hMap -eq [IntPtr]::Zero){
        $hMap=[NativeMethods]::OpenFileMappingA([NativeMethods]::FILE_MAP_ALL_ACCESS,$false,'SOVEREIGN_BEACON_V1')
        if($hMap -eq [IntPtr]::Zero){Start-Sleep -Milliseconds 50}
    }
    if($hMap -eq [IntPtr]::Zero){ throw 'OpenFileMapping failed' }

    $pMap=[NativeMethods]::MapViewOfFile($hMap,[NativeMethods]::FILE_MAP_ALL_ACCESS,0,0,[UIntPtr]::new(65536))
    if($pMap -eq [IntPtr]::Zero){ throw 'MapViewOfFile failed' }
    if(-not (Wait-OrchReady $pMap 5000)){ throw 'Magic cookie timeout' }

    $access=[NativeMethods]::EVENT_MODIFY_STATE -bor [NativeMethods]::SYNCHRONIZE
    $hCmd=[NativeMethods]::OpenEventA($access,$false,'SOVEREIGN_CMD_EVENT')
    $hResp=[NativeMethods]::OpenEventA($access,$false,'SOVEREIGN_RESP_EVENT')
    $hCancel=[NativeMethods]::OpenEventA($access,$false,'SOVEREIGN_CANCEL_EVENT')
    if($hCmd -eq [IntPtr]::Zero -or $hResp -eq [IntPtr]::Zero){ throw 'OpenEvent failed' }

    $st=Send-Command $pMap $hCmd $hResp $CMD_GET_STATUS $null $ResponseTimeoutMs
    if(-not $st.Success -or $st.Status -ne $RESP_OK){ throw 'STATUS failed before load' }

    Write-Host '[LOAD] Loading model...' -ForegroundColor Yellow
    $m=[Text.Encoding]::ASCII.GetBytes($ModelPath)
    if($m.Length -gt 4095){ throw 'Model path too long' }
    $ld=Send-Command $pMap $hCmd $hResp $CMD_LOAD_MODEL $m 30000
    if(-not $ld.Success){ throw 'LOAD timeout' }
    if($ld.Status -ne $RESP_OK){ throw "LOAD failed status=$($ld.Status)" }
    Write-Host '[LOAD] OK' -ForegroundColor Green

    if($Streamer -eq 0 -or $Streamer -eq 1){
        $streamCmd = if($Streamer -eq 1){ $CMD_STREAM_START } else { $CMD_STREAM_STOP }
        $streamSet = Send-Command $pMap $hCmd $hResp $streamCmd $null $ResponseTimeoutMs
        if(-not $streamSet.Success){ throw "STREAM set timeout (streamer=$Streamer)" }
        if($streamSet.Status -ne $RESP_OK){ throw "STREAM set failed status=$($streamSet.Status) streamer=$Streamer" }

        $streamStatus = Send-Command $pMap $hCmd $hResp $CMD_STREAM_STATUS $null $ResponseTimeoutMs
        if(-not $streamStatus.Success){ throw "STREAM status timeout (streamer=$Streamer)" }
        if($streamStatus.Status -ne $RESP_OK){ throw "STREAM status failed status=$($streamStatus.Status) streamer=$Streamer" }
        Write-Host "[STREAM] Applied streamer=$Streamer" -ForegroundColor Yellow
    }

    $rng=[Random]::new($Seed);$pass=0;$cancelOk=0;$lat=New-Object System.Collections.Generic.List[double]

    for($i=1;$i -le $RequestCount;$i++){
        $cancel=($rng.Next(100) -lt $CancelPercent)
        $inf=Send-Command $pMap $hCmd $hResp $CMD_INFER ([Text.Encoding]::ASCII.GetBytes("v5 request $i")) $ResponseTimeoutMs
        if(-not $inf.Success){ throw "Request ${i}: infer response timeout" }
        if($inf.Status -eq $RESP_BUSY){ throw "Request ${i}: infer returned BUSY" }
        if($inf.Status -ne $RESP_OK){ throw "Request ${i}: infer failed status=$($inf.Status)" }

        if($cancel){
            Start-Sleep -Milliseconds ($rng.Next(30,250))
            $can=Send-Command $pMap $hCmd $hResp $CMD_CANCEL_INFER $null $ResponseTimeoutMs
            if(-not $can.Success){ throw "Request ${i}: cancel timeout" }
            if($can.Status -ne $RESP_OK -and $can.Status -ne $RESP_CANCELLED -and $can.Status -ne $RESP_NOT_READY){ throw "Request ${i}: cancel status=$($can.Status)" }
            $done=Wait-InferenceComplete $pMap 5000
            if(-not $done.Success){ throw "Request ${i}: cancel recovery timeout state=$($done.State)" }
            $cancelOk++
        } else {
            $done=Wait-InferenceComplete $pMap $InferenceTimeoutMs
            if(-not $done.Success){ throw "Request ${i}: completion timeout state=$($done.State) ms=$($done.Ms)" }
            $lat.Add([double]$done.Ms)
            $pass++
        }

        if($Verbose -or ($i % 10 -eq 0)){
            $t=Read-U64 $pMap $OFF_TELEM_TOKENS
            Write-Host ("  [{0}/{1}] ok cancel={2} tokens={3}" -f $i,$RequestCount,$cancel,$t)
        }
    }

    $avg= if($lat.Count -gt 0){ [Math]::Round(($lat|Measure-Object -Average).Average,2) } else {0}
    $p95= if($lat.Count -gt 0){ $s=$lat|Sort-Object; $idx=[Math]::Min($s.Count-1,[int][Math]::Floor($s.Count*0.95)); [Math]::Round($s[$idx],2) } else {0}

    Write-Host '================================================================' -ForegroundColor Cyan
    Write-Host 'RESULTS' -ForegroundColor Cyan
    Write-Host '================================================================' -ForegroundColor Cyan
    Write-Host "Pass: $pass/$RequestCount"
    Write-Host "Cancel-Recovered: $cancelOk"
    Write-Host "Avg Inference Completion (ms): $avg"
    Write-Host "P95 Inference Completion (ms): $p95"
    Write-Host '? REGRESSION GATE v5 PASSED' -ForegroundColor Green

    Cleanup-All
    exit 0
}
catch{
    Write-Host "`n? REGRESSION GATE v5 FAILED" -ForegroundColor Red
    Write-Host ("Reason: {0}" -f $_.Exception.Message) -ForegroundColor Red
    Cleanup-All
    exit 1
}
