param([string]$Path)

$tokens = $null
$errs = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$tokens, [ref]$errs)
if ($errs -and $errs.Count -gt 0) {
  $errs | ForEach-Object { "{0}:{1}:{2} {3}" -f $_.Extent.File, $_.Extent.StartLineNumber, $_.Extent.StartColumnNumber, $_.Message }
}
else {
  'OK'
}
