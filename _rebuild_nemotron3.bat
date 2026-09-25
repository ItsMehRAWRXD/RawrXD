@echo off
setlocal enabledelayedexpansion

:: Set up MSVC x64 environment
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"

set "BUILD=f:\~dev\rawrxd\build"
set "SRC=f:\~dev\rawrxd\src\deep2"
set "OUT=%BUILD%\bin\Release"

echo --- Replacing Deep2Engine.obj in InferenceEngine.lib ---
cd /d "%BUILD%\Release"

:: Remove old Deep2Engine.obj from library
lib.exe /nologo /remove:"InferenceEngine.dir\Release\Deep2Engine.obj" InferenceEngine.lib
if errorlevel 1 (
    echo WARN: remove failed (may already be gone or different path), continuing...
)

:: Add new Deep2Engine_new.obj
lib.exe /nologo /out:InferenceEngine_new.lib "%BUILD%\Deep2Engine_new.obj" InferenceEngine.lib
if errorlevel 1 (
    echo FAILED: could not create new library
    exit /b 1
)

:: Replace original library with new one
move /y InferenceEngine_new.lib InferenceEngine.lib

echo --- Building rawr.exe with updated library ---
set "INC1=-I f:\~dev\rawrxd\include -I f:\~dev\rawrxd\src -I f:\~dev\rawrxd\src\deep2 -I f:\~dev\rawrxd\src\inference -I f:\~dev\rawrxd\src\engine -I f:\~dev\rawrxd\src\core -I f:\~dev\rawrxd\src\codec -I f:\~dev\rawrxd\src\masm -I f:\~dev\rawrxd\src\runtime\governance -I f:\~dev\rawrxd\src\deep2\expert_cache"
set "INC2=-I C:\VulkanSDK\1.4.357.0\Include"
set "DEFS=/D WIN32 /D _WINDOWS /D NDEBUG /D _CRT_SECURE_NO_WARNINGS /D NOMINMAX /D WIN32_LEAN_AND_MEAN /D RAWR_INTENT_GUARD_ENABLED=1 /D RAWR_INTENT_VALIDATION_ENABLED=1 /D RAWR_PATCH_TRANSACTION_ENABLED=1 /D RAWR_CAPABILITY_TOKENS_ENABLED=1 /D RAWR_HOTPATCH_JOURNAL_ENABLED=1 /D RAWR_PATCH_FIREWALL_ENABLED=1 /D RAWR_REFLECTOR_AGENT_ENABLED=1 /D RAWR_ATOMIC_ACTIVATION_ENABLED=1 /D RAWR_ROLLBACK_FIRST_CLASS_ENABLED=1 /D RAWR_MODEL_ADAPTER_ENABLED=1 /D RAWR_INTENT_EMERGENCY_BYPASS=0 /D RAWR_ENABLE_VULKAN=1 /D VULKAN_HPP_DISPATCH_LOADER_DYNAMIC=1 /D RAWR_HAS_VULKAN=1"
set "FLAGS=/O2 /arch:AVX512 /EHsc /W4 /std:c++20 /MT /GS- /sdl-"
set "VULKLIB=C:\VulkanSDK\1.4.357.0\Lib\vulkan-1.lib"
set "LIBS=%BUILD%\Release\InferenceEngine.lib dxgi.lib !VULKLIB! shlwapi.lib dbghelp.lib winhttp.lib bcrypt.lib advapi32.lib crypt32.lib psapi.lib kernel32.lib user32.lib gdi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib comdlg32.lib"

cl.exe %FLAGS% %DEFS% %INC1% %INC2% "%SRC%\rawr_run.cpp" "%SRC%\rawrxd_run_modelname_001.cpp" /Fe"%OUT%\rawr.exe" /link %LIBS%
if errorlevel 1 (
    echo FAILED: rawr.exe
    exit /b 1
)

echo BUILD_OK rawr.exe
