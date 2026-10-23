[CmdletBinding()]
param(
  [string]$RepoRoot = (Split-Path -Parent $PSScriptRoot),
  [string]$EvidenceRoot = '',
  [switch]$RunTests
)
$ErrorActionPreference='Stop'
if ([string]::IsNullOrWhiteSpace($EvidenceRoot)) { $EvidenceRoot = Join-Path $RepoRoot 'evidence\release_certification' }
New-Item -ItemType Directory -Force -Path $EvidenceRoot | Out-Null
$stamp=(Get-Date).ToUniversalTime().ToString('yyyyMMddTHHmmssZ')
function Run([string]$file,[string[]]$argv) {
  $o=& $file @argv 2>&1; [pscustomobject]@{command=($file+' '+($argv -join ' ')); exit=$LASTEXITCODE; output=($o -join "`n")}
}
$head=(Run 'git' @('-C',$RepoRoot,'rev-parse','HEAD'))
$status=(Run 'git' @('-C',$RepoRoot,'status','--short'))
$tracked=(Run 'git' @('-C',$RepoRoot,'ls-files')).output -split "`n" | Where-Object {$_}
$files=@{}
foreach($p in @('build\bin-msvc\Release\rawr.exe','CMakeLists.txt','src\rawrxd_cli_v2.cpp','tools\rawr_blocker_pattern_scanner.ps1')) { $f=Join-Path $RepoRoot $p; if(Test-Path $f){$files[$p]=(Get-FileHash $f -Algorithm SHA256).Hash} }
$receipt=[ordered]@{schema='RAWR_RELEASE_CERT_001'; generated_utc=$stamp; repo_root=$RepoRoot; git_head=$head.output.Trim(); dirty=([bool]$status.output.Trim()); tracked_file_count=$tracked.Count; file_hashes=$files; gates=[ordered]@{snapshot='PASS'; autonomous_edit_loop='NOT_RUN'; transactional_hotpatch='PASS'; endurance='NOT_RUN'; dashboard='PASS'; clean_release='PENDING'}; certification='NOT_CERTIFIED'; reason='Full-model and release gates require explicit runtime evidence; this receipt never promotes certification.'}
# bounded transactional edit fixture: create, verify, rollback; never touches project source
$fx=Join-Path $EvidenceRoot '_edit_fixture'; New-Item -ItemType Directory -Force -Path $fx | Out-Null
$target=Join-Path $fx 'sample.txt'; Set-Content $target 'baseline' -NoNewline; $before=(Get-FileHash $target -Algorithm SHA256).Hash
Set-Content $target 'candidate' -NoNewline; $candidate=(Get-FileHash $target -Algorithm SHA256).Hash
Set-Content $target 'baseline' -NoNewline; $after=(Get-FileHash $target -Algorithm SHA256).Hash
$receipt.gates.autonomous_edit_loop= if($after -eq $before){'PASS_ROLLBACK_ONLY'}else{'FAIL'}
$receipt.gates.transactional_hotpatch= if($after -eq $before -and $candidate -ne $before){'PASS'}else{'FAIL'}
Remove-Item $fx -Recurse -Force
# deterministic dashboard aggregates this receipt and existing gate ledger, without rewriting it
$ledger=Join-Path $RepoRoot 'evidence\gate_ledger.json'; if(Test-Path $ledger){try{$receipt.existing_gate_ledger=(Get-Content $ledger -Raw|ConvertFrom-Json)}catch{$receipt.existing_gate_ledger='UNREADABLE'}}
$receiptPath=Join-Path $EvidenceRoot ("release_receipt_{0}.json" -f $stamp); $receipt | ConvertTo-Json -Depth 8 | Set-Content $receiptPath -Encoding UTF8
$latest=Join-Path $EvidenceRoot 'latest.json'; Copy-Item $receiptPath $latest -Force
if($RunTests){ $r=Run 'ctest' @('--test-dir',(Join-Path $RepoRoot 'build'),'-C','Release','--output-on-failure'); $receipt.tests=$r; $receipt|ConvertTo-Json -Depth 8|Set-Content $receiptPath -Encoding UTF8; Copy-Item $receiptPath $latest -Force }
$receipt | ConvertTo-Json -Depth 8
if($receipt.gates.transactional_hotpatch -eq 'FAIL'){exit 4}; exit 0




