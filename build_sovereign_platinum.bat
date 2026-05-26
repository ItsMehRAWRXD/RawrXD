@echo off
set "VCDIR=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64"
set "VCINCLUDE=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\include"
set "VCLIB=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\lib\x64"
set "SDK=C:\Program Files (x86)\Windows Kits\10"
set "SDKVER=10.0.22621.0"
set "INCLUDE=%VCINCLUDE%;%SDK%\Include\%SDKVER%\shared;%SDK%\Include\%SDKVER%\um;%SDK%\Include\%SDKVER%\ucrt;D:\rawrxd\src"
set "LIB=%VCLIB%;%SDK%\Lib\%SDKVER%\um\x64;%SDK%\Lib\%SDKVER%\ucrt\x64"
set "PATH=%VCDIR%;%PATH%"

set ML64=ml64.exe
set CC=cl.exe
set LD=link.exe
set SRC=D:\rawrxd\src
set OBJ=obj
set BIN=bin

if not exist %OBJ% mkdir %OBJ%
if not exist %BIN% mkdir %BIN%

echo [1/21] Assembling Sovereign Kernels...
%ML64% /c /nologo /Fo%OBJ%\Sovereign_Entry.obj %SRC%\Sovereign_Entry.asm
%ML64% /c /nologo /Fo%OBJ%\Sovereign_File_Mapper.obj %SRC%\Sovereign_File_Mapper.asm
%ML64% /c /nologo /Fo%OBJ%\Sovereign_SharedMem.obj %SRC%\Sovereign_SharedMem.asm
%ML64% /c /nologo /Fo%OBJ%\Sovereign_OS_Glue.obj %SRC%\Sovereign_OS_Glue.asm
%ML64% /c /nologo /Fo%OBJ%\Sovereign_Risk_Gate.obj %SRC%\sovereign_risk_gate.asm
%ML64% /c /nologo /Fo%OBJ%\Sovereign_Slab_Allocator.obj %SRC%\Sovereign_Slab_Allocator.asm
%ML64% /c /nologo /Fo%OBJ%\Sovereign_Panic.obj %SRC%\Sovereign_Panic.asm
%ML64% /c /nologo /Fo%OBJ%\Titan_MoE_Core_Platinum.obj %SRC%\Titan_MoE_Core_Platinum.asm
%ML64% /c /nologo /Fo%OBJ%\Sovereign_Ultra_HFT.obj %SRC%\Sovereign_Ultra_HFT.asm

echo [9/21] Assembling Math Substrate Kernels...
%ML64% /c /nologo /Fo%OBJ%\Titan_Token_Stream_Buffer.obj %SRC%\Titan_Token_Stream_Buffer.asm
%ML64% /c /nologo /Fo%OBJ%\Titan_ArgMax_Selector.obj %SRC%\Titan_ArgMax_Selector.asm
%ML64% /c /nologo /Fo%OBJ%\Titan_Tensor_Transpose.obj %SRC%\Titan_Tensor_Transpose.asm
%ML64% /c /nologo /Fo%OBJ%\Titan_SIMD_Packer.obj %SRC%\Titan_SIMD_Packer.asm
%ML64% /c /nologo /Fo%OBJ%\Titan_Expert_Router.obj %SRC%\Titan_Expert_Router.asm
%ML64% /c /nologo /Fo%OBJ%\Titan_Performance_Monitor.obj %SRC%\Titan_Performance_Monitor.asm
%ML64% /c /nologo /Fo%OBJ%\Titan_GEMV_FMA_Core.obj %SRC%\Titan_GEMV_FMA_Core.asm
%ML64% /c /nologo /Fo%OBJ%\Titan_Dequant_Unpack.obj %SRC%\Titan_Dequant_Unpack.asm
%ML64% /c /nologo /Fo%OBJ%\Titan_Elementwise_SiLU.obj %SRC%\Titan_Elementwise_SiLU.asm
%ML64% /c /nologo /Fo%OBJ%\Titan_Quantize_Block.obj %SRC%\Titan_Quantize_Block.asm
%ML64% /c /nologo /Fo%OBJ%\Titan_Softmax_Phase.obj %SRC%\Titan_Softmax_Phase.asm
%ML64% /c /nologo /Fo%OBJ%\Titan_RMS_Norm.obj %SRC%\Titan_RMS_Norm.asm
%ML64% /c /nologo /Fo%OBJ%\Titan_Vector_Hadamard_Bias.obj %SRC%\Titan_Vector_Hadamard_Bias.asm
%ML64% /c /nologo /Fo%OBJ%\Titan_Thread_Barrier.obj %SRC%\Titan_Thread_Barrier.asm
%ML64% /c /nologo /Fo%OBJ%\Titan_Vector_Scale_Add.obj %SRC%\Titan_Vector_Scale_Add.asm

echo [20/21] Compiling Platinum Main (C++)...
%CC% /c /O2 /GS- /EHsc /arch:AVX2 /Fo%OBJ%\Titan_Main_Platinum.obj %SRC%\Titan_Main_Platinum.cpp

echo [21/21] Linking Sovereign Platinum Engine...
%LD% /SUBSYSTEM:CONSOLE /NODEFAULTLIB /ENTRY:main /OUT:%BIN%\Sovereign_Platinum_Engine.exe ^
  %OBJ%\Titan_Main_Platinum.obj ^
  %OBJ%\Sovereign_Entry.obj ^
  %OBJ%\Sovereign_File_Mapper.obj ^
  %OBJ%\Sovereign_SharedMem.obj ^
  %OBJ%\Sovereign_OS_Glue.obj ^
  %OBJ%\Sovereign_Risk_Gate.obj ^
  %OBJ%\Sovereign_Slab_Allocator.obj ^
  %OBJ%\Sovereign_Panic.obj ^
  %OBJ%\Sovereign_Ultra_HFT.obj ^
  %OBJ%\Titan_MoE_Core_Platinum.obj ^
  %OBJ%\Titan_Token_Stream_Buffer.obj ^
  %OBJ%\Titan_ArgMax_Selector.obj ^
  %OBJ%\Titan_Tensor_Transpose.obj ^
  %OBJ%\Titan_SIMD_Packer.obj ^
  %OBJ%\Titan_Expert_Router.obj ^
  %OBJ%\Titan_Performance_Monitor.obj ^
  %OBJ%\Titan_GEMV_FMA_Core.obj ^
  %OBJ%\Titan_Dequant_Unpack.obj ^
  %OBJ%\Titan_Elementwise_SiLU.obj ^
  %OBJ%\Titan_Quantize_Block.obj ^
  %OBJ%\Titan_Softmax_Phase.obj ^
  %OBJ%\Titan_RMS_Norm.obj ^
  %OBJ%\Titan_Vector_Hadamard_Bias.obj ^
  %OBJ%\Titan_Thread_Barrier.obj ^
  %OBJ%\Titan_Vector_Scale_Add.obj ^
  kernel32.lib

if %ERRORLEVEL% NEQ 0 (
    echo [FATAL] Build failed.
    exit /b 1
)

echo [OK] Sovereign_Platinum_Engine.exe built successfully.
