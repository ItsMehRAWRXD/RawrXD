@echo off
REM build_sovereign_platinum_complete.bat
REM Production build pipeline for Sovereign Platinum Engine
REM Assembles all Titan kernels and links with zero CRT dependency

set ML64=ml64.exe
set LINK=link.exe
set SRC=D:\rawrxd\src
set OBJ=obj
set BIN=bin

if not exist %OBJ% mkdir %OBJ%
if not exist %BIN% mkdir %BIN%

echo [1/18] Assembling Sovereign Entry...
%ML64% /c /nologo /Fo%OBJ%\Sovereign_Entry.obj %SRC%\Sovereign_Entry.asm

echo [2/18] Assembling Model Mapper...
%ML64% /c /nologo /Fo%OBJ%\Sovereign_Model_Mapper.obj %SRC%\Sovereign_Model_Mapper.asm

echo [3/18] Assembling Shared Memory...
%ML64% /c /nologo /Fo%OBJ%\Sovereign_SharedMem.obj %SRC%\Sovereign_SharedMem.asm

echo [4/18] Assembling Token Stream Buffer...
%ML64% /c /nologo /Fo%OBJ%\Titan_Token_Stream_Buffer.obj %SRC%\Titan_Token_Stream_Buffer.asm

echo [5/18] Assembling ArgMax Selector...
%ML64% /c /nologo /Fo%OBJ%\Titan_ArgMax_Selector.obj %SRC%\Titan_ArgMax_Selector.asm

echo [6/18] Assembling Tensor Transpose...
%ML64% /c /nologo /Fo%OBJ%\Titan_Tensor_Transpose.obj %SRC%\Titan_Tensor_Transpose.asm

echo [7/18] Assembling SIMD Packer...
%ML64% /c /nologo /Fo%OBJ%\Titan_SIMD_Packer.obj %SRC%\Titan_SIMD_Packer.asm

echo [8/18] Assembling Expert Router...
%ML64% /c /nologo /Fo%OBJ%\Titan_Expert_Router.obj %SRC%\Titan_Expert_Router.asm

echo [9/18] Assembling Performance Monitor...
%ML64% /c /nologo /Fo%OBJ%\Titan_Performance_Monitor.obj %SRC%\Titan_Performance_Monitor.asm

echo [10/18] Assembling GEMV FMA Core...
%ML64% /c /nologo /Fo%OBJ%\Titan_GEMV_FMA_Core.obj %SRC%\Titan_GEMV_FMA_Core.asm

echo [11/18] Assembling Dequant Unpack...
%ML64% /c /nologo /Fo%OBJ%\Titan_Dequant_Unpack.obj %SRC%\Titan_Dequant_Unpack.asm

echo [12/18] Assembling Elementwise SiLU...
%ML64% /c /nologo /Fo%OBJ%\Titan_Elementwise_SiLU.obj %SRC%\Titan_Elementwise_SiLU.asm

echo [13/18] Assembling Quantize Block...
%ML64% /c /nologo /Fo%OBJ%\Titan_Quantize_Block.obj %SRC%\Titan_Quantize_Block.asm

echo [14/18] Assembling Softmax Phase...
%ML64% /c /nologo /Fo%OBJ%\Titan_Softmax_Phase.obj %SRC%\Titan_Softmax_Phase.asm

echo [15/18] Assembling RMS Norm...
%ML64% /c /nologo /Fo%OBJ%\Titan_RMS_Norm.obj %SRC%\Titan_RMS_Norm.asm

echo [16/18] Assembling Vector Hadamard Bias...
%ML64% /c /nologo /Fo%OBJ%\Titan_Vector_Hadamard_Bias.obj %SRC%\Titan_Vector_Hadamard_Bias.asm

echo [17/18] Assembling Thread Barrier...
%ML64% /c /nologo /Fo%OBJ%\Titan_Thread_Barrier.obj %SRC%\Titan_Thread_Barrier.asm

echo [18/18] Assembling NEW Scale-Add kernel...
%ML64% /c /nologo /Fo%OBJ%\Titan_Vector_Scale_Add.obj %SRC%\Titan_Vector_Scale_Add.asm

echo [*] Linking Sovereign Platinum Engine...
%LINK% /SUBSYSTEM:CONSOLE /NODEFAULTLIB /ENTRY:main /OUT:%BIN%\Sovereign_Platinum_Engine.exe ^
  %OBJ%\Sovereign_Entry.obj ^
  %OBJ%\Sovereign_Model_Mapper.obj ^
  %OBJ%\Sovereign_SharedMem.obj ^
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
  kernel32.lib ucrt.lib

if %ERRORLEVEL% NEQ 0 (
    echo [FATAL] Link failed.
    exit /b 1
)

echo [OK] Sovereign_Platinum_Engine.exe built successfully.
