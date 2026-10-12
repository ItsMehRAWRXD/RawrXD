$ErrorActionPreference = 'SilentlyContinue'
$vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
Write-Output "vswhere: $vswhere exists=$(Test-Path -LiteralPath $vswhere)"
if (Test-Path -LiteralPath $vswhere) {
    $vsPath = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
    Write-Output "VS install: $vsPath"
    $vctools = Join-Path $vsPath 'VC\Tools\MSVC'
    if (Test-Path -LiteralPath $vctools) {
        $versions = Get-ChildItem -LiteralPath $vctools | Sort-Object Name
        $latest = $versions | Select-Object -Last 1 -ExpandProperty Name
        Write-Output "MSVC version: $latest"
        $cl = Join-Path $vctools "$latest\bin\Hostx64\x64\cl.exe"
        Write-Output "cl.exe: $cl exists=$(Test-Path -LiteralPath $cl)"
    }
}
foreach ($cmd in 'g++','clang++','cl') {
    $c = Get-Command $cmd
    if ($c) { Write-Output "$cmd => $($c.Source)" } else { Write-Output "$cmd => NOT FOUND" }
}
