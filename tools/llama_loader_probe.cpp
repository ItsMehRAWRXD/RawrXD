// RAWRXD_ORACLE_LOADER_PROBE_001
//
// Standalone DLL dependency probe. Links only against Windows system libraries, so
// it can run even when the oracle harness cannot reach main().
//
// Loads the reference llama.dll by EXPLICIT absolute path with
// LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_DEFAULT_DIRS, which makes
// Windows resolve that DLL's dependencies relative to its own directory instead of
// whichever llama.dll happens to be first on the search path.
//
// This answers one question precisely: can the reference DLL set load at all, and if
// not, what error code does the loader return?
//
// Build:
//   cl /nologo /EHsc /std:c++17 tools\llama_loader_probe.cpp /Fe:tools\llama_loader_probe.exe
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <cstdio>

int wmain() {
    const wchar_t* path = L"F:\\llama.cpp-ref\\build\\bin\\llama.dll";

    const HMODULE module = LoadLibraryExW(
        path,
        nullptr,
        LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_DEFAULT_DIRS);

    if (!module) {
        const DWORD error = GetLastError();
        std::printf("LOAD_FAILED=%lu\n", static_cast<unsigned long>(error));
        // Name the common codes so the log is self-explanatory.
        switch (error) {
            case 2:   std::puts("  ERROR_FILE_NOT_FOUND\n"); break;
            case 126: std::puts("  ERROR_MOD_NOT_FOUND (a dependent module is missing)\n"); break;
            case 127: std::puts("  ERROR_PROC_NOT_FOUND (a required entry point is missing)\n"); break;
            case 193: std::puts("  ERROR_BAD_EXE_FORMAT (architecture mismatch)\n"); break;
            default: break;
        }
        return 1;
    }

    std::puts("LOAD_PASS");

    // Absolute path of the module actually loaded, so the log proves which DLL won.
    {
        wchar_t resolved[MAX_PATH] = {0};
        const DWORD n = GetModuleFileNameW(module, resolved, MAX_PATH);
        if (n > 0 && n < MAX_PATH) {
            std::printf("LOADED_FROM=%ls\n", resolved);
        }
    }

    const char* symbols[] = {
        "llama_backend_init",
        "llama_backend_free",
        "llama_model_load_from_file",
        "llama_init_from_model",
        "llama_batch_init",
        "llama_batch_free",
        "llama_decode",
        "llama_get_logits_ith",
        "llama_vocab_n_tokens",
        "llama_model_get_vocab",
        "llama_model_free",
        "llama_free",
    };

    size_t missing = 0;
    for (const char* symbol : symbols) {
        const FARPROC proc = GetProcAddress(module, symbol);
        std::printf("%s=%s\n", symbol, proc ? "PASS" : "MISSING");
        if (!proc) ++missing;
    }
    std::printf("EXPORTS_MISSING=%zu\n", missing);

    FreeLibrary(module);
    return missing == 0 ? 0 : 3;
}