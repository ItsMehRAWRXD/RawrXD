call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul
cd /d "g:\~dev\llama.cpp\build-hybrid-r105"
cmake "g:\~dev\llama.cpp" -G Ninja -DCMAKE_BUILD_TYPE=Release -DCMAKE_C_COMPILER=cl -DCMAKE_CXX_COMPILER=cl -DGGML_VULKAN=ON -DGGML_NATIVE=ON -DLLAMA_BUILD_COMMON=OFF -DLLAMA_BUILD_TESTS=OFF -DLLAMA_BUILD_EXAMPLES=OFF -DLLAMA_BUILD_SERVER=OFF -DLLAMA_BUILD_TOOLS=OFF -DGGML_CCACHE=OFF
if errorlevel 1 exit /b 1
cmake --build . --config Release -j %NUMBER_OF_PROCESSORS%
if errorlevel 1 exit /b 1
cd /d "g:\~dev\rawrxd\evidence\REAP_STRATA_UNSLOTH_OLLAMA_BENCH_001\deep2_ornith_hybrid_load_r105"
cl /nologo /O2 /EHsc /std:c++17 /I"g:\~dev\llama.cpp\include" /I"g:\~dev\llama.cpp\ggml\include" ornith_hybrid_load_probe.cpp /Fe:ornith_hybrid_load_probe.exe /link /LIBPATH:"g:\~dev\llama.cpp\build-hybrid-r105\src" /LIBPATH:"g:\~dev\llama.cpp\build-hybrid-r105\bin" llama.lib
exit /b %errorlevel%
