# Independent implementation: does NOT use the gate's helper or regex engine path.
# Rule restated: the first non-blank, non-whitespace line of the file, trimmed,
# matches ^//\s*STUB\b  -> the file is a pure stub.
$root='F:\~dev\rawrxd\src'
$files = Get-ChildItem $root -Recurse -File | Where-Object { $_.Extension -in '.cpp','.c','.h','.hpp','.cc','.cxx' }
$stubs = New-Object System.Collections.Generic.List[string]
$totalBytes = 0
foreach ($f in $files) {
  $fb = $null
  foreach ($line in [System.IO.File]::ReadLines($f.FullName)) {
    if (-not [string]::IsNullOrWhiteSpace($line)) { $fb = $line.Trim(); break }
  }
  if ($null -ne $fb -and $fb -match '^//\s*STUB\b') { $stubs.Add($f.FullName); $totalBytes += $f.Length }
}
"FILES_SCANNED=$($files.Count)"
"PURE_STUB=$($stubs.Count)"
"PURE_STUB_TOTAL_BYTES=$totalBytes"
"PURE_STUB_MEAN_BYTES=$([int]($totalBytes / [Math]::Max(1,$stubs.Count)))"
"MAX_BYTES=$((($stubs | ForEach-Object { (Get-Item $_).Length }) | Measure-Object -Maximum).Maximum)"
"ANY_OVER_500_BYTES=$(@($stubs | Where-Object { (Get-Item $_).Length -gt 500 }).Count)"
"BY_TOP_DIR:"
$stubs | ForEach-Object { ($_ -replace [regex]::Escape($root+'\_'),'' -split '\\')[0] } | Group-Object | Sort-Object Count -Descending | ForEach-Object { "  {0,4}  {1}" -f $_.Count,$_.Name }
