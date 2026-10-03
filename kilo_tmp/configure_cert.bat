call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
cmake -S F:\~dev\rawrxd -B F:\~dev\build_cert -G "Visual Studio 17 2022" -A x64 -DBUILD_DEEP2_STREAMER_CERT=ON
