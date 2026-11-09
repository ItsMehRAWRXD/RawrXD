# Build iterations

1. Incremental candidate build in `build_ext_host_001`: passed after adding `src/ollama_client.cpp`; both requested targets linked and the deployment step completed.
2. Fresh configure in `build_ext_host_clean_001`: completed successfully with non-fatal existing warnings about optional fallbacks, validation libraries, and Qt6.
3. Fresh clean build in `build_ext_host_clean_001`: all 1,440 steps completed; both final links succeeded; no unresolved external, LNK1120, or fatal linker diagnostics were present.

No executable was launched.
