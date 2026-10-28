@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul
cd /d "g:\~dev\rawrxd\evidence\AGENTIC_CAMELLIA_STUB_GATE_001"
cl /nologo /c /EHsc /O2 /DRAWR_HAS_MASM=1 /Foagentic_camellia_gate_masm1.obj agentic_camellia_gate_smoke.cpp > cl_masm1.log 2>&1
cl /nologo /c /EHsc /O2 /DRAWR_HAS_MASM=0 /Foagentic_camellia_gate_masm0.obj agentic_camellia_gate_smoke.cpp > cl_masm0.log 2>&1
dumpbin /SYMBOLS agentic_camellia_gate_masm1.obj > dumpbin_masm1.txt
dumpbin /SYMBOLS agentic_camellia_gate_masm0.obj > dumpbin_masm0.txt
