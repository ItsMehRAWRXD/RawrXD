@echo off
"C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\MSBuild\Current\Bin\MSBuild.exe" "F:\~dev\rawrxd\build\InferenceEngine.vcxproj" /p:Configuration=Release /p:Platform=x64 /t:Rebuild
