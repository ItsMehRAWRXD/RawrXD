@echo off
call "C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Auxiliary\Build\vcvars64.bat"
cd /d d:\rawrxd\build-master

link /nologo seal_corpus.obj golden_master.obj interpreter_seal.obj /out:seal_corpus.exe /subsystem:console
