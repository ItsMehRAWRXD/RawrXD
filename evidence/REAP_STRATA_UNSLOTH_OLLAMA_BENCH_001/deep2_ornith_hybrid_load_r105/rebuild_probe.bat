call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul
cd /d "g:\~dev\rawrxd\evidence\REAP_STRATA_UNSLOTH_OLLAMA_BENCH_001\deep2_ornith_hybrid_load_r105"
cl /nologo /O2 /MD /EHsc /I "g:\~dev\llama.cpp\include" /I "g:\~dev\llama.cpp\ggml\include" ornith_hybrid_load_probe.cpp /Fe:ornith_hybrid_load_probe.exe /link /LIBPATH:"g:\~dev\llama.cpp\build-hybrid-r105\bin" /LIBPATH:"g:\~dev\llama.cpp\build-hybrid-r105\src" /LIBPATH:"g:\~dev\llama.cpp\build-hybrid-r105\ggml\src" llama.lib ggml.lib ggml-base.lib
exit /b %errorlevel%
