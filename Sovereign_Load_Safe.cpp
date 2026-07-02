#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdint.h>
#include <cstring>

extern "C" uint64_t SOVEREIGN_LOAD_MODEL(const char* path);
extern "C" volatile LONG g_LastLoadResult;

static volatile LONG g_LastLoadException = 0;

static constexpr LONG LOAD_RESULT_ERROR_FILE_NOT_FOUND = -1;
static constexpr LONG LOAD_RESULT_ERROR_UNKNOWN = -99;

static bool IsInvalidPathPointer(const char* path) {
    return path == nullptr || reinterpret_cast<uintptr_t>(path) == UINTPTR_MAX;
}

extern "C" __declspec(dllexport) uint64_t Sovereign_LoadModel_Safe(const char* path) {
    // Boundary sanity gate: never enter ASM loader with null/-1/empty path.
    if (IsInvalidPathPointer(path) || path[0] == '\0') {
        InterlockedExchange(&g_LastLoadException, ERROR_INVALID_PARAMETER);
        InterlockedExchange(&g_LastLoadResult, LOAD_RESULT_ERROR_UNKNOWN);
        return 0;
    }

    const DWORD attrs = GetFileAttributesA(path);
    if (attrs == INVALID_FILE_ATTRIBUTES || (attrs & FILE_ATTRIBUTE_DIRECTORY) != 0) {
        InterlockedExchange(&g_LastLoadException, ERROR_FILE_NOT_FOUND);
        InterlockedExchange(&g_LastLoadResult, LOAD_RESULT_ERROR_FILE_NOT_FOUND);
        return 0;
    }

    __try {
        uint64_t h = SOVEREIGN_LOAD_MODEL(path);
        InterlockedExchange(&g_LastLoadException, 0);
        return h;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        InterlockedExchange(&g_LastLoadException, (LONG)GetExceptionCode());
        return 0;
    }
}

extern "C" __declspec(dllexport) uint32_t Sovereign_GetLastLoadException() {
    return (uint32_t)InterlockedCompareExchange(&g_LastLoadException, 0, 0);
}
