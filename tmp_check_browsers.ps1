$ErrorActionPreference = 'SilentlyContinue'
# WebView2 runtime registry check
$wv2 = 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}'
if (Test-Path $wv2) { Write-Output 'WebView2 runtime: INSTALLED' } else { Write-Output 'WebView2 runtime: NOT in registry' }
# Installed browsers
$paths = @(
  'C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe',
  'C:\Program Files\Microsoft\Edge\Application\msedge.exe',
  'C:\Program Files\Google\Chrome\Application\chrome.exe',
  'C:\Program Files (x86)\Google\Chrome\Application\chrome.exe'
)
foreach ($p in $paths) { if (Test-Path $p) { Write-Output ("BROWSER: " + $p) } }
# WebView2 loader DLL
$loader = 'C:\Program Files (x86)\Microsoft\EdgeWebView\Application\WebView2Loader.dll'
if (Test-Path $loader) { Write-Output ("WebView2Loader: " + $loader) }
