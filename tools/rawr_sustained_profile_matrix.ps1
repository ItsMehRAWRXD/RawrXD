[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$Model,
    [string]$Bench = (Join-Path $PSScriptRoot '..\build\bin-msvc\Release\deep2_bench_tps.exe'),
    [string]$Output = (Join-Path $PSScriptRoot '..\evidence\sustained_profile_matrix.json'),
    [int]$Runs = 2,
    [switch]$Run
)

# Produces the repeatable 8/32/128/256-token profiling matrix requested by
# RAWRXD_NEXT_15_MOVES_006.  It never changes model files or GPU policy.  By
# default it validates the executable and prints the planned matrix; -Run is
# required to launch the benchmark explicitly.
$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$modelPath = (Resolve-Path $Model).Path
$benchPath = (Resolve-Path $Bench -ErrorAction Stop).Path
$lengths = @(8,32,128,256)
$records = [System.Collections.Generic.List[object]]::new()

foreach ($n in $lengths) {
    $tokens = ((1..$n) -join ' ')
    foreach ($mode in @('single','dual')) {
        $rec = [ordered]@{
            tokens=$n; mode=$mode; runs=$Runs; status='PLANNED';
            exit_code=$null; stdout=''; stderr='';
        }
        if ($Run) {
            # Dual mode is an admission request only. The native selector must
            # reject it if two usable discrete Vulkan devices are unavailable.
            $old = $env:RAWRXD_GPU_POLICY
            try {
                $env:RAWRXD_GPU_POLICY = if ($mode -eq 'dual') {'dual'} else {'single'}
                $outText = & $benchPath --model $modelPath --tokens $tokens --decode $n --runs $Runs 2>&1 | Out-String
                $rec.stdout = $outText
                $rec.exit_code = $LASTEXITCODE
                $rec.status = if ($LASTEXITCODE -eq 0) {'PASS'} else {'FAIL'}
                # A claimed GPU run with a CPU fallback is never promoted by
                # this harness; preserve the evidence for the certification gate.
                if ($outText -match 'cpu_calls=[1-9]|fallback=(?!<none>)[^\s]+') {
                    $rec.status = 'FAIL_CPU_FALLBACK'
                }
            } catch {
                $rec.status='ERROR'; $rec.stderr=$_.Exception.Message
            } finally {
                if ($null -eq $old) { Remove-Item Env:RAWRXD_GPU_POLICY -ErrorAction SilentlyContinue }
                else { $env:RAWRXD_GPU_POLICY=$old }
            }
        }
        $records.Add([pscustomobject]$rec)
    }
}

$payload = [ordered]@{
    schema='rawrxd.sustained-profile-matrix.v1'; generated_utc=(Get-Date).ToUniversalTime().ToString('o')
    model=$modelPath; benchmark=$benchPath; runs=$Runs; launched=[bool]$Run
    certification='NOT_CERTIFIED'; records=@($records)
}
$dir = Split-Path $Output -Parent
New-Item -ItemType Directory -Force -Path $dir | Out-Null
$payload | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $Output -Encoding utf8
$payload | ConvertTo-Json -Depth 4
if (-not $Run) { exit 0 }
if (@($records | Where-Object status -notin @('PASS')).Count -gt 0) { exit 4 }
exit 0
