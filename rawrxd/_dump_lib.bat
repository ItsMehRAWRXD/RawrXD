@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >NUL 2>NUL
lib /LIST "F:\~dev\rawrxd\build\Release\InferenceEngine.lib" > "F:\~dev\rawrxd\_lib_list.txt" 2>&1
echo DONE
