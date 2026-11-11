$ErrorActionPreference = 'SilentlyContinue'
# Find WebView2Loader.dll
$candidates = @(
  'C:\Program Files (x86)\Microsoft\EdgeWebView\Application\WebView2Loader.dll',
  'C:\Program Files (x86)\Microsoft\Edge\Application\WebView2Loader.dll'
)
foreach ($c in $candidates) { if (Test-Path $c) { Write-Output ("LOADER: " + $c) } }
# Search Windows Kits for WebView2Loader
Get-ChildItem 'C:\Program Files (x86)\Windows Kits' -Recurse -Filter 'WebView2Loader.dll' -ErrorAction SilentlyContinue | ForEach-Object { Write-Output ("LOADER: " + $_.FullName) }
# Check the WebView2 runtime dir for the loader
Get-ChildItem 'C:\Program Files (x86)\Microsoft\EdgeWebView\Application\154.0.4258.62' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name
