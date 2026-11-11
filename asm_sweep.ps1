$Script:ml64 = 'C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\ml64.exe'
$Script:inc1 = 'd:\rawrxd\include'
$Script:inc2 = 'd:\rawrxd\src\asm'
$Script:outDir = 'd:\rawrxd\asm_obj_sweep'
$Script:errLog = 'd:\rawrxd\asm_sweep_errors.log'
$Script:okLog = 'd:\rawrxd\asm_sweep_ok.log'
New-Item -ItemType Directory -Force -Path $outDir | Out-Null
if (Test-Path $errLog) { Remove-Item $errLog }
if (Test-Path $okLog)  { Remove-Item $okLog }
$Script:files = Get-Content d:\rawrxd\asm_inventory.txt
$Script:total = $files.Count
$files | ForEach-Object -Parallel {
$Script:f = $_
$Script:name = [System.IO.Path]::GetFileNameWithoutExtension($f)
$Script:obj = "${using:outDir}\$name.obj"
$Script:out = "${using:outDir}\$name.out"
$Script:err = "${using:outDir}\$name.err"
$Script:flag = "${using:outDir}\$name.flag"
$Script:proc = Start-Process -FilePath ${using:ml64} -ArgumentList "/c /W3 /nologo /I `"${using:inc1}`" /I `"${using:inc2}`" /Fo `"$obj`" `"$f`"" -NoNewWindow -Wait -PassThru -RedirectStandardOutput $out -RedirectStandardError $err
    if ($proc.ExitCode -ne 0) {
        [void][System.IO.File]::WriteAllText($flag, "FAIL`n" + (Get-Content $err -Raw))
    } else {
        [void][System.IO.File]::WriteAllText($flag, "OK")
    }
} -ThrottleLimit 8
$Script:okFiles = Get-ChildItem -Path $outDir -Filter *.flag | Where-Object { (Get-Content $_.FullName -TotalCount 1) -eq 'OK' } | ForEach-Object { $_.BaseName }
$Script:failFiles = Get-ChildItem -Path $outDir -Filter *.flag | Where-Object { (Get-Content $_.FullName -TotalCount 1) -ne 'OK' } | ForEach-Object { $_.BaseName }
foreach ($name in $okFiles) {
    "$name" | Out-File -FilePath $okLog -Append
}
foreach ($name in $failFiles) {
    "$name" | Out-File -FilePath $errLog -Append
}
Write-Host "Sweep complete. OK=$($okFiles.Count) Fail=$($failFiles.Count) Total=$total"
