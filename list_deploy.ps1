Add-Type -AssemblyName System.IO.Compression.FileSystem
$zip = [System.IO.Compression.ZipFile]::OpenRead('F:\rawrxd\dist\RawrXD-14.7.3-Windows-x64.zip')
foreach ($e in $zip.Entries) {
    Write-Host ('{0,60} {1,10} bytes' -f $e.FullName, $e.Length)
}
$zip.Dispose()