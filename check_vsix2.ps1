Add-Type -AssemblyName System.IO.Compression.FileSystem
$zip = [System.IO.Compression.ZipFile]::OpenRead('d:\rawrxd\rawrxd-extension.vsix')
foreach ($e in $zip.Entries) {
    Write-Host ('{0,60} {1,10} bytes' -f $e.FullName, $e.Length)
}
$zip.Dispose()