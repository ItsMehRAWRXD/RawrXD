#Requires -Version 5.1
[CmdletBinding()]
param([string]$ProjectPath, [string]$UserDataDirectory)
$ErrorActionPreference = 'Stop'
& (Join-Path $PSScriptRoot 'Verify-PortableRelease.ps1') -PackageDirectory $PSScriptRoot | Out-Null
$exe = Join-Path $PSScriptRoot 'RawrXD-Win32IDE-Native-Ext.exe'
$workingDirectory = $PSScriptRoot
$arguments = @()
if ($ProjectPath) {
    $resolvedProject = (Resolve-Path -LiteralPath $ProjectPath).Path
    if ($resolvedProject.Contains('"')) { throw 'A project path cannot contain a quotation mark.' }
    $workingDirectory = if (Test-Path -LiteralPath $resolvedProject -PathType Container) {
        $resolvedProject
    } else { Split-Path -Parent $resolvedProject }
    $arguments = @('"' + $resolvedProject + '"')
}
if ($UserDataDirectory) {
    $profilePath = [IO.Path]::GetFullPath($UserDataDirectory)
    if ($profilePath.Contains('"')) { throw 'A profile path cannot contain a quotation mark.' }
    $arguments += '"--user-data-dir=' + $profilePath.TrimEnd('\') + '"'
}
if ($arguments.Count) {
    Start-Process -FilePath $exe -ArgumentList $arguments -WorkingDirectory $workingDirectory
} else {
    Start-Process -FilePath $exe -WorkingDirectory $workingDirectory
}
