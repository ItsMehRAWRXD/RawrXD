$ErrorActionPreference='Continue'
cmd /c '"C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\Common7\Tools\VsDevCmd.bat" -arch=amd64 >nul && cl /nologo /Fe:"F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\fixtures\term_hello.exe" "F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\fixtures\term_hello.c"'
if (Test-Path 'F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\fixtures\term_hello.exe') { & 'F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\fixtures\term_hello.exe'; Write-Output ("TERM_EXIT_" + $LASTEXITCODE) } else { Write-Output 'TERM_COMPILE_FAIL' }
