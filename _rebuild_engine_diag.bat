@echo off
setlocal
set "MSVC=C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC\14.44.35207"
set "VK_INC=C:\VulkanSDK\1.4.357.0\Include"
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul
if errorlevel 1 (
    echo vcvars64.bat failed
    exit /b 1
)
set "OUT=build_ide_audit\_Deep2Engine_patched_MT.obj"
echo === Compiling Deep2Engine.cpp ===
"%MSVC%\bin\Hostx64\x64\cl.exe" /nologo /c /MT /O2 /std:c++17 /W3 /EHsc ^
    /D_RAWRXD_BUILD_ID="audit_diag" ^
    /D_CRT_SECURE_NO_WARNINGS ^
    /I"%VK_INC%" ^
    /I"src/deep2" ^
    /I"src" ^
    /I"build_ide_audit" ^
    /Fo"%OUT%" ^
    "src/deep2\Deep2Engine.cpp"
if errorlevel 1 (
    echo COMPILE_FAILED
    exit /b 1
)
echo === Compiling Sampler.cpp ===
"%MSVC%\bin\Hostx64\x64\cl.exe" /nologo /c /MT /O2 /std:c++17 /W3 /EHsc ^
    /D_RAWRXD_BUILD_ID="audit_diag" ^
    /D_CRT_SECURE_NO_WARNINGS ^
    /I"%VK_INC%" ^
    /I"src/deep2" ^
    /I"src" ^
    /I"build_ide_audit" ^
    /Fo"build_ide_audit\_Sampler_patched_MT.obj" ^
    "src/deep2\Sampler.cpp"
if errorlevel 1 (
    echo SAMPLER_COMPILE_FAILED
    exit /b 1
)
echo === Compiling lifecycle test ===
"%MSVC%\bin\Hostx64\x64\cl.exe" /nologo /c /MT /O2 /std:c++17 /W3 /EHsc ^
    /D_RAWRXD_BUILD_ID="audit_diag" ^
    /D_CRT_SECURE_NO_WARNINGS ^
    /I"%VK_INC%" ^
    /I"src/deep2" ^
    /I"src" ^
    /I"build_ide_audit" ^
    /Fo"build_ide_audit\_lifecycle_test_MT.obj" ^
    "tools\deep2_generation_lifecycle_test.cpp"
if errorlevel 1 (
    echo TEST_COMPILE_FAILED
    exit /b 1
)
echo === Linking ===
"%MSVC%\bin\Hostx64\x64\link.exe" /nologo /OUT:bin\deep2_generation_lifecycle_test.exe ^
    /LIBPATH:"%MSVC%\lib\x64" ^
    /LIBPATH:"build_ide_audit\Release" ^
    /LIBPATH:"C:\VulkanSDK\1.4.357.0\Lib" ^
    libcpmt.lib ^
    vulkan-1.lib ^
    build_ide_audit\_Deep2Engine_patched_MT.obj ^
    build_ide_audit\_Sampler_patched_MT.obj ^
    build_ide_audit\_lifecycle_test_MT.obj ^
    InferenceEngine_patched.lib
if errorlevel 1 (
    echo LINK_FAILED
    exit /b 1
)
echo === Done ===
endlocal
