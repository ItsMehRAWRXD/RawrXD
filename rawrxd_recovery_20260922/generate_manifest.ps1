param(
    [string]$BasePath,
    [string]$OutputFile
)
$baseUri = [System.Uri]((Get-Item $BasePath).FullName)
$files = Get-ChildItem -Path $BasePath -Recurse -File -ErrorAction SilentlyContinue
$lines = foreach ($f in $files) {
    $rel = [System.Uri]::new($baseUri, $f.FullName).ToString().Replace($baseUri.ToString(), "").TrimStart("/").Replace("/", "\")
    $hash = (Get-FileHash -Path $f.FullName -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
    if (-not $hash) { $hash = "HASH_ERROR" }
    "$rel|$($f.Length)|$hash|$($f.LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss"))"
}
$lines | Sort-Object | Out-File -FilePath $OutputFile -Encoding UTF8
"Count: $($lines.Count)"
