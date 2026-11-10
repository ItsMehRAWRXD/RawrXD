@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvarsall.bat" x64
link.exe /OUT:F:\rawrxd\tmp_build\modelgenie_ir_executor.exe F:\rawrxd\rawrxd_modelgenie_ir_executor.obj F:\rawrxd\ModelGenome.obj F:\rawrxd\ModelGenomeReader.obj /OPT:REF /OPT:ICF