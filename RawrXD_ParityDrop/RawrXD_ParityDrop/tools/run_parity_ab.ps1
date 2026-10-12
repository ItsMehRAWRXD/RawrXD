# RAWRXD_DEEP2_PACKED_DOT_AB_001. Windows PowerShell 7+ or PowerShell 5.1.
# No third-party modules or Python packages. Requires user's own built engine,
# GGUF, the full token sequence, and the immutable reference logit directory.
param(
  [Parameter(Mandatory=$true)][string]$Exe,
  [Parameter(Mandatory=$true)][string]$GGUF,
  [Parameter(Mandatory=$true)][string]$GenomeEvidence,
  [Parameter(Mandatory=$true)][string]$TokensFile,
  [Parameter(Mandatory=$true)][string]$ReferenceDir,
  [Parameter(Mandatory=$true)][string]$OutputRoot,
  [ValidateRange(1,4096)][int]$Count=20
)
$ErrorActionPreference='Stop'
foreach($f in @($Exe,$GGUF,$TokensFile)) { if(!(Test-Path -LiteralPath $f -PathType Leaf)){throw "Missing file: $f"} }
foreach($d in @($GenomeEvidence,$ReferenceDir)) {if(!(Test-Path -LiteralPath $d -PathType Container)){throw "Missing directory: $d"}}
$raw=[System.IO.File]::ReadAllText($TokensFile)
$Tokens=@($raw -split '[,\s\[\]]+' | Where-Object { $_ -match '^\d+$' })
if($Tokens.Count -ne $Count) {throw "Need exactly $Count teacher-forced input tokens; got $($Tokens.Count)"}
$base=Join-Path $OutputRoot 'baseline'
$packed=Join-Path $OutputRoot 'packed'
New-Item -Path $base,$packed -ItemType Directory -Force | Out-Null
# Harness loads ModelGenome from evidence_dir, and writes logits there.
# Clone only genome metadata into A/B evidence dirs; never modify original.
# Avoid copying large existing logits/captures into both new run folders.
# The genome loader's small metadata files are sufficient for initialization.
$genomeFiles=Get-ChildItem -LiteralPath $GenomeEvidence -File | Where-Object {
  $_.Length -le 16MB -and $_.Name -notmatch '^(native_tf_logits_pos|ref_logits_pos|probe_step|layer0_pos|diff_)'
}
foreach($dir in @($base,$packed)) {
  foreach($f in $genomeFiles) {
    Copy-Item -LiteralPath $f.FullName -Destination (Join-Path $dir $f.Name) -Force
  }
}
# Hash exe, model, and exact input sequence before invoking either mode.
$manifest=[ordered]@{
  certificate_id='RAWRXD_DEEP2_PACKED_DOT_AB_001'
  executable_path=(Resolve-Path -LiteralPath $Exe).Path
  executable_sha256=(Get-FileHash -LiteralPath $Exe -Algorithm SHA256).Hash
  model_path=(Resolve-Path -LiteralPath $GGUF).Path
  model_sha256=(Get-FileHash -LiteralPath $GGUF -Algorithm SHA256).Hash
  token_file_sha256=(Get-FileHash -LiteralPath $TokensFile -Algorithm SHA256).Hash
  reference_path=(Resolve-Path -LiteralPath $ReferenceDir).Path
  count=$Count
  default_mode='CERTIFIED_VARIANT_A_UNCHANGED'
  candidate_mode='RAWRXD_PARITY_PACKED_DOT=1'
}
$manifest | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $OutputRoot 'run_manifest.json') -Encoding UTF8
$old=[Environment]::GetEnvironmentVariable('RAWRXD_PARITY_PACKED_DOT','Process')
$baselineLog=Join-Path $base 'run.log'
$packedLog=Join-Path $packed 'run.log'
$oldErrorAction=$ErrorActionPreference
try {
  [Environment]::SetEnvironmentVariable('RAWRXD_PARITY_PACKED_DOT',$null,'Process')
  # PowerShell 5.1 turns native stderr into nonterminating ErrorRecords.
  # Preserve exit-code authority rather than treating diagnostic stderr as failure.
  $ErrorActionPreference='Continue'
  & $Exe $GGUF $base --teacher-forced @Tokens *> $baselineLog
  if($LASTEXITCODE -ne 0){throw "Baseline exited $LASTEXITCODE"}
  [Environment]::SetEnvironmentVariable('RAWRXD_PARITY_PACKED_DOT','1','Process')
  & $Exe $GGUF $packed --teacher-forced @Tokens *> $packedLog
  if($LASTEXITCODE -ne 0){throw "Packed path exited $LASTEXITCODE"}
} finally {
  $ErrorActionPreference=$oldErrorAction
  [Environment]::SetEnvironmentVariable('RAWRXD_PARITY_PACKED_DOT',$old,'Process')
}
$here=Split-Path -Parent $MyInvocation.MyCommand.Path
& py -3 (Join-Path $here 'compare_parity.py') --reference $ReferenceDir --baseline $base --candidate $packed --count $Count --require-packed-counter --output (Join-Path $OutputRoot 'packed_dot_ab.json')
if($LASTEXITCODE -ne 0){throw "Candidate not promotable (or comparison incomplete), exit $LASTEXITCODE"}
