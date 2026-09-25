$ErrorActionPreference = 'Stop'
$required = @(
  'deep2_model_identity.inc',
  'deep2_model_tensors.inc',
  'deep2_model_quant.inc',
  'deep2_system_used.inc',
  'deep2_stamp_schema.inc',
  'deep2_execution_image.rxi',
  'deep2_probe.trace'
)
foreach ($f in $required) {
  if (-not (Test-Path $f)) { throw "MISSING=$f" }
  $i = Get-Item $f
  if ($i.Length -le 0) { throw "EMPTY=$f" }
  "{0} SIZE={1}" -f $f,$i.Length
}
$identity = Get-Content .\deep2_model_identity.inc -Raw
foreach ($needle in @('DEEP2_MODEL_GGUF_VERSION','DEEP2_MODEL_FILE_BYTES','DEEP2_MODEL_TENSOR_COUNT','DEEP2_MODEL_METADATA_COUNT','DEEP2_MODEL_TENSOR_DATA_START')) {
  if ($identity -notmatch [regex]::Escape($needle)) { throw "IDENTITY_FIELD_MISSING=$needle" }
}
'OUTPUT_VERIFY=PASS'
