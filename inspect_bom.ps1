$b = [IO.File]::ReadAllBytes('F:\~dev\CMakeLists.txt')
Write-Host ('Bytes 0-4: ' + ($b[0..4] -join ' '))
