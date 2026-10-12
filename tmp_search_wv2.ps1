$ErrorActionPreference = 'SilentlyContinue'
# Search whole system for WebView2Loader.dll
Get-ChildItem 'C:\' -Recurse -Filter 'WebView2Loader.dll' -ErrorAction SilentlyContinue |
  Select-Object -First 10 -ExpandProperty FullName
Write-Output '---HEADERS---'
Get-ChildItem 'C:\' -Recurse -Filter 'WebView2.h' -ErrorAction SilentlyContinue |
  Select-Object -First 10 -ExpandProperty FullName
Write-Output '---LIBS---'
Get-ChildItem 'C:\' -Recurse -Filter 'WebView2.lib' -ErrorAction SilentlyContinue |
  Select-Object -First 10 -ExpandProperty FullName
