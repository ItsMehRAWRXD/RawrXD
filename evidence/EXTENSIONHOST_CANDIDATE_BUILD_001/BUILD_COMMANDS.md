# Configure command
cmake -S G:\~dev\rawrxd-ext-candidate-clean -B G:\~dev\rawrxd-ext-candidate-clean\build_ext_host_001 -G Ninja -DCMAKE_BUILD_TYPE=Release -DRAWRXD_BUILD_WIN32IDE=ON

# Build command
cmake --build G:\~dev\rawrxd-ext-candidate-clean\build_ext_host_001 --config Release --target RawrXD-ExtensionHost RawrXD-Win32IDE -j 1

Result: configure PASS; worker target linked; IDE target failed at final link with LNK1120 (18 unresolved externals). No IDE launch or runtime execution performed.
