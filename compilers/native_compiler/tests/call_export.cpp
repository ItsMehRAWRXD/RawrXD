// Calls an exported function and reports what happened, including the
// machine code at the resolved address.
#include <windows.h>
#include <stdio.h>

int main(int argc, char** argv) {
    if (argc < 2) { printf("usage: call_export <dll> [name]\n"); return 2; }
    const char* name = (argc > 2) ? argv[2] : "RawrxdAdd";

    HMODULE m = LoadLibraryA(argv[1]);
    if (!m) { printf("LoadLibrary failed: %lu\n", GetLastError()); return 1; }

    FARPROC p = GetProcAddress(m, name);
    printf("GetProcAddress('%s') = %p (error %lu)\n", name, (void*)p, GetLastError());
    if (!p) return 1;

    unsigned char* code = (unsigned char*)p;
    printf("machine code at the resolved address:");
    for (int i = 0; i < 12; ++i) printf(" %02X", code[i]);
    printf("\n");
    printf("  8B C1 -> mov eax, ecx   03 D0 -> add eax, edx   83 C0 01 -> add eax,1\n");

    typedef int (*AddFn)(int, int);
    AddFn fn = (AddFn)p;
    printf("fn(20, 21) = %d  (expected 42)\n", fn(20, 21));
    printf("fn(1, 2)   = %d  (expected 4)\n", fn(1, 2));
    printf("fn(100, 0) = %d  (expected 101)\n", fn(100, 0));

    FreeLibrary(m);
    return 0;
}
