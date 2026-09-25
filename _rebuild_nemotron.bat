@echo off
setlocal enabledelayedexpansion

:: Set up MSVC x64 environment
set "VSWHERE=C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
if not exist "%VSWHERE%" (
    echo ERROR: vcvars64.bat not found
    exit /b 1
)
call "%VSWHERE%"

set "BUILD=f:\~dev\rawrxd\build"
set "SRC=f:\~dev\rawrxd\src\deep2"
set "OUT=%BUILD%\bin\Release"

if not exist "%OUT%" mkdir "%OUT%"

echo --- Recompiling Deep2Engine.cpp with nemotron_h_moe fix ---
cl.exe /c /I"F:\~dev\rawrxd\include" /IC:\VulkanSDK\1.4.357.0\Include /I"F:\~dev\rawrxd\src" /I"F:\~dev\rawrxd\src\deep2" /I"F:\~dev\rawrxd\src\inference" /I"F:\~dev\rawrxd\src\engine" /I"F:\~dev\rawrxd\src\core" /I"F:\~dev\rawrxd\src\codec" /I"F:\~dev\rawrxd\src\masm" /I"F:\~dev\rawrxd\src\runtime\governance" /nologo /W0 /WX- /diagnostics:column /sdl- /O2 /Ob2 /D _MBCS /D WIN32 /D _WINDOWS /D NDEBUG /D RAWR_HAS_VULKAN=1 /D RAWR_VULKAN_AVAILABLE=1 /D RAWRXD_STRICT_PRODUCTION_PROFILE=0 /D RAWR_STANDALONE_INFERENCE=1 /D RAWR_HAS_SOVEREIGN_ENGINES=1 /D RAWRXD_PRODUCTION_STRIP_STUB_SOURCES=0 /D RAWR_HAS_MASM=1 /D RAWRXD_LINK_QUADBUFFER_ASM=1 /D RAWRXD_LINK_INFERENCE_KERNELS_ASM=1 /D RAWRXD_LINK_ANALYZER_DISTILLER_ASM=0 /D RAWRXD_LINK_STREAMING_ORCHESTRATOR_ASM=0 /D RAWRXD_LINK_TELEMETRY_KERNEL_ASM=1 /D RAWRXD_LINK_PROMETHEUS_EXPORTER_ASM=1 /D RAWRXD_LINK_SELFPATCH_AGENT_ASM=1 /D RAWRXD_LINK_SOURCEEDIT_KERNEL_ASM=1 /D RAWRXD_LINK_VISION_PROJECTION_ASM=0 /D RAWRXD_LINK_REVERSE_ENGINEERED_ASM=1 /D RAWRXD_LINK_DUAL_ENGINE_QUANTUM_BEACON_ASM=0 /D RAWRXD_LINK_UNIFIED_OVERCLOCK_GOVERNOR_ASM=0 /D RAWRXD_LINK_CODEBASE_AUDIT_SYSTEM_ASM=0 /D RAWRXD_LINK_ADVANCED_DEOBFUSCATOR_ASM=1 /D RAWRXD_LINK_PATTERN_RECONSTRUCTOR_ASM=1 /D HAS_BRUTAL_GZIP_MASM=1 /D _CRT_SECURE_NO_WARNINGS /D NOMINMAX /D WIN32_LEAN_AND_MEAN /D RAWR_INTENT_GUARD_ENABLED=1 /D RAWR_INTENT_VALIDATION_ENABLED=1 /D RAWR_PATCH_TRANSACTION_ENABLED=1 /D RAWR_CAPABILITY_TOKENS_ENABLED=1 /D RAWR_HOTPATCH_JOURNAL_ENABLED=1 /D RAWR_PATCH_FIREWALL_ENABLED=1 /D RAWR_REFLECTOR_AGENT_ENABLED=1 /D RAWR_ATOMIC_ACTIVATION_ENABLED=1 /D RAWR_ROLLBACK_FIRST_CLASS_ENABLED=1 /D RAWR_MODEL_ADAPTER_ENABLED=1 /D RAWR_INTENT_EMERGENCY_BYPASS=0 /D RAWR_ENABLE_VULKAN=1 /D VULKAN_HPP_DISPATCH_LOADER_DYNAMIC=1 /D "CMAKE_INTDIR=\"Release\"" /EHsc /MT /GS- /arch:AVX512 /std:c++20 /Fo"%BUILD%\Deep2Engine_new.obj" /Fd"%BUILD%\Deep2Engine_new.pdb" /external:W0 /TP /external:I "C:/Program Files (x86)/Microsoft Visual Studio/2022/BuildTools/VC/Tools/MSVC/14.44.35207/include" /external:I "C:/Program Files (x86)/Windows Kits/10/Include/10.0.26100.0/ucrt" /external:I "C:/Program Files (x86)/Windows Kits/10/Include/10.0.26100.0/shared" /external:I "C:/Program Files (x86)/Windows Kits/10/Include/10.0.26100.0/um" /external:I "C:/Program Files (x86)/Windows Kits/10/Include/10.0.26100.0/winrt" /external:I "D:/rawrxd/Ship/webview2/build/native/include" "F:\~dev\rawrxd\src\deep2\Deep2Engine.cpp"
if errorlevel 1 (
    echo FAILED: Deep2Engine.cpp compilation
    exit /b 1
)

echo --- Building test_generate_313_tokens.cpp ---
cl.exe /nologo /std:c++20 /O2 /EHsc /W4 /I"F:\~dev\rawrxd\include" /I"F:\~dev\rawrxd\src\deep2" /I"F:\~dev\rawrxd\src\deep2\expert_cache" /I"F:\~dev\rawrxd\src\tokenizer" /I"F:\~dev\rawrxd\src" /I"F:\~dev\rawrxd\src\inference" /I"F:\~dev\rawrxd\src\engine" /I"F:\~dev\rawrxd\src\core" /I"F:\~dev\rawrxd\src\codec" /I"F:\~dev\rawrxd\src\masm" /I"F:\~dev\rawrxd\src\runtime\governance" /I"C:\VulkanSDK\1.4.357.0\Include" /DWIN32 /D_WINDOWS /DNDEBUG /D_CRT_SECURE_NO_WARNINGS /DNOMINMAX /DWIN32_LEAN_AND_MEAN /DRAWR_INTENT_GUARD_ENABLED=1 /DRAWR_INTENT_VALIDATION_ENABLED=1 /DRAWR_PATCH_TRANSACTION_ENABLED=1 /DRAWR_CAPABILITY_TOKENS_ENABLED=1 /DRAWR_HOTPATCH_JOURNAL_ENABLED=1 /DRAWR_PATCH_FIREWALL_ENABLED=1 /DRAWR_REFLECTOR_AGENT_ENABLED=1 /DRAWR_ATOMIC_ACTIVATION_ENABLED=1 /DRAWR_ROLLBACK_FIRST_CLASS_ENABLED=1 /DRAWR_MODEL_ADAPTER_ENABLED=1 /DRAWR_INTENT_EMERGENCY_BYPASS=0 /DRAWR_ENABLE_VULKAN=1 /DVULKAN_HPP_DISPATCH_LOADER_DYNAMIC=1 /DRAWR_HAS_VULKAN=1 /Fo"%BUILD%\test_generate_313_tokens.dir\Release\test_generate_313_tokens.obj" /c "F:\~dev\rawrxd\src\deep2\test_generate_313_tokens.cpp"
if errorlevel 1 (
    echo FAILED: test_generate_313_tokens.cpp compilation
    exit /b 1
)

echo --- Linking test_generate_313_tokens.exe with new Deep2Engine.obj ---
link.exe /nologo /MACHINE:X64 /OUT:"%OUT%\test_generate_313_tokens.exe" "%BUILD%\test_generate_313_tokens.dir\Release\test_generate_313_tokens.obj" "%BUILD%\Deep2Engine_new.obj" "%BUILD%\Release\InferenceEngine.lib" "F:\~dev\rawrxd\src\deep2\ResidencyTrace.obj" "F:\~dev\rawrxd\src\deep2\QuantKB.obj" "C:\VulkanSDK\1.4.357.0\Lib\vulkan-1.lib" shlwapi.lib psapi.lib dbghelp.lib winhttp.lib bcrypt.lib advapi32.lib crypt32.lib dxgi.lib pdh.lib kernel32.lib user32.lib gdi32.lib winspool.lib shell32.lib ole32.lib oleaut32.lib uuid.lib comdlg32.lib
if errorlevel 1 (
    echo FAILED: link
    exit /b 1
)

echo BUILD_OK
echo Output: %OUT%\test_generate_313_tokens.exe
