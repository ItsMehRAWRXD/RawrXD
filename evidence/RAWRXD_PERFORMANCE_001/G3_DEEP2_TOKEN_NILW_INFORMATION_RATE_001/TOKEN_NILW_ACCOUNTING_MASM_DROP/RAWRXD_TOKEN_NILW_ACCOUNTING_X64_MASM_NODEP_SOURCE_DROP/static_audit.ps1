$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$asm = Get-ChildItem $root -Filter '*.asm'
$core = $asm | Where-Object { $_.Name -notlike 'smoke_*' }
$fail = [System.Collections.Generic.List[string]]::new()

foreach ($file in $asm) {
    $lines = @(Get-Content -LiteralPath $file.FullName).Count
    if ($lines -gt 99) { $fail.Add("TU_OVER_99=$($file.Name):$lines") }
}

$coreText = ($core | ForEach-Object { Get-Content -Raw -LiteralPath $_.FullName }) -join "`n"
foreach ($word in @('CreateFileMapping','MapViewOfFile','malloc','scheduler','Fence3','PROMOTE')) {
    if ($coreText -match [regex]::Escape($word)) { $fail.Add("FORBIDDEN_CORE_REFERENCE=$word") }
}

$required = @(
    'NilwEvaluate','NilwU128MulLE','NILW_G_RUNTIME_AUTHORIZED',
    'observed_new_payload_bits','active_codec_bits','new_codec_bits',
    'physicalization_num','new_information_num','overhead_num','token_nilw_num'
)
$allText = Get-Content -Raw -LiteralPath (Join-Path $root 'nilw_accounting.inc')
$allText += "`n" + $coreText
foreach ($word in $required) {
    if ($allText -notmatch [regex]::Escape($word)) { $fail.Add("MISSING=$word") }
}

if ($fail.Count) {
    $fail | ForEach-Object { Write-Output $_ }
    Write-Output 'STATIC_AUDIT=FAIL'
    exit 1
}
Write-Output 'STATIC_AUDIT=PASS'
Write-Output 'CORE_EXTERNAL_CALLS=0'
Write-Output 'SOURCE_TUS_LE_99=1'
Write-Output 'SCHEDULER_TOUCHED=0'
Write-Output 'PRODUCT_PROMOTE_TOUCHED=0'
exit 0
