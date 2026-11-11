# MinGW removed. Use Build-IDE-Custom.ps1 with your custom MASM C++ compiler.
# Example: .\Build-IDE-Custom.ps1 -CxxCompiler "C:\path\to\your\custom_c++.exe"
param()
Write-Host "MinGW build removed. Use Build-IDE-Custom.ps1 with -CxxCompiler <path to your custom MASM C++ compiler>." -ForegroundColor Yellow
Write-Host "Example: .\Build-IDE-Custom.ps1 -CxxCompiler 'C:\compilers\rawrxd_cpp.exe'" -ForegroundColor Cyan
exit 1
