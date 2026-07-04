$Script:dllPath = "D:\lazy init ide\bin\temp_build\RawrXD_PatternBridge.dll"
$Script:typeName = "RawrXD_Verifier_$(Get-Date -Format 'yyyyMMddHHmmss')"
$Script:escaped = $dllPath -replace '\\','\\'

$Script:csharp = @"
using System;
using System.Runtime.InteropServices;
public static class $typeName
{
    [DllImport("${escaped}", CallingConvention = CallingConvention.Cdecl)]
    public static extern int InitializePatternEngine();
}
"@

try {
    Add-Type $csharp
    Write-Host "Verifying $dllPath with type $typeName..."
$Script:expr = "[$typeName]::InitializePatternEngine()"
$Script:res = Invoke-Expression $expr
    if ($res -eq 1) { 
        Write-Host "InitializePatternEngine returned: $res (SUCCESS)" -ForegroundColor Green 
    } else { 
        Write-Host "InitializePatternEngine returned: $res" -ForegroundColor Yellow 
    }
} catch {
    Write-Error $_
}
