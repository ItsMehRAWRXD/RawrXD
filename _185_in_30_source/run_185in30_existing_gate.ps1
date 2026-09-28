param(
    [Parameter(Mandatory=$true)][string]$Bench,
    [Parameter(Mandatory=$true)][string]$Model,
    [string]$Receipt=".\RAWRXD_DEEP2_185_IN_30_001.txt"
)

$ErrorActionPreference="Stop"
$Bench=(Resolve-Path -LiteralPath $Bench).Path
$Model=(Resolve-Path -LiteralPath $Model).Path
$so=[IO.Path]::GetTempFileName()
$se=[IO.Path]::GetTempFileName()

try {
    $sw=[Diagnostics.Stopwatch]::StartNew()
    $p=Start-Process -FilePath $Bench -ArgumentList @($Model,"185") `
        -RedirectStandardOutput $so -RedirectStandardError $se `
        -NoNewWindow -Wait -PassThru
    $sw.Stop()

    $err=Get-Content -Raw $se
    function M([string]$n) {
        $m=[regex]::Match($err,"(?m)^"+[regex]::Escape($n)+"=([^\r\n]+)")
        if($m.Success){$m.Groups[1].Value.Trim()}else{$null}
    }

    $gen=M "GENERATED"
    $real=M "REAL_GPU_FORWARD"
    $fb=M "UNPLANNED_FALLBACKS"
    $strict=M "STRICT_GPU_VIOLATIONS"
    $eng=M "DECODE_TPS_ENGINE"
    $qpc=M "DECODE_TPS_QPC"

    $sec=$sw.Elapsed.TotalSeconds
    $req=185.0/30.0
    $wall=if($sec -gt 0 -and $gen){[double]$gen/$sec}else{0.0}

    $pass=($gen -eq "185" -and $sec -le 30.0 -and
           $real -eq "1" -and $fb -eq "0" -and $strict -eq "0" -and
           $wall -ge $req)

    @(
        "GATE=RAWRXD_DEEP2_185_IN_30_001"
        "TARGET_TOKENS=185"
        "TIME_LIMIT_SECONDS=30.000000"
        ("REQUIRED_TPS={0:F6}" -f $req)
        ("GENERATED={0}" -f $gen)
        ("PROCESS_WALL_SECONDS={0:F6}" -f $sec)
        ("PROCESS_WALL_TPS={0:F6}" -f $wall)
        ("DECODE_TPS_ENGINE={0}" -f $eng)
        ("DECODE_TPS_QPC={0}" -f $qpc)
        ("REAL_GPU_FORWARD={0}" -f $real)
        ("UNPLANNED_FALLBACKS={0}" -f $fb)
        ("STRICT_GPU_VIOLATIONS={0}" -f $strict)
        ("VERDICT={0}" -f $(if($pass){"PASS"}else{"HOLD"}))
    ) | Set-Content -Encoding UTF8 $Receipt

    Get-Content $Receipt
    if($pass){exit 0}else{exit 1}
}
finally {
    Remove-Item $so,$se -Force -ErrorAction SilentlyContinue
}
