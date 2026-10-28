#include <stdio.h>
#include <windows.h>
extern int asm_camellia256_set_key(const unsigned char* key32);
static int filter(EXCEPTION_POINTERS* ep) {
    EXCEPTION_RECORD* er = ep->ExceptionRecord;
    CONTEXT* ctx = ep->ContextRecord;
    printf("EXC=0x%08lX addr=%p rip=%p rsp=%p rcx=%p rdx=%p\n",
           (unsigned long)er->ExceptionCode,
           (void*)er->ExceptionAddress,
           (void*)ctx->Rip,
           (void*)ctx->Rsp,
           (void*)ctx->Rcx,
           (void*)ctx->Rdx);
    if (er->NumberParameters >= 2) {
        printf("  av_type=%p av_addr=%p\n",
               (void*)er->ExceptionInformation[0],
               (void*)er->ExceptionInformation[1]);
    }
    fflush(stdout);
    return EXCEPTION_EXECUTE_HANDLER;
}
int main(void) {
    unsigned char key[32];
    int i, rc;
    DWORD n = 0;
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    WriteFile(h, "probe enter\r\n", 13, &n, 0);
    printf("set_key fn=%p\n", (void*)&asm_camellia256_set_key); fflush(stdout);
    for (i = 0; i < 32; i++) key[i] = (unsigned char)i;
    __try {
        WriteFile(h, "call set_key\r\n", 14, &n, 0);
        rc = asm_camellia256_set_key(key);
        printf("set_key rc=%d\n", rc); fflush(stdout);
    } __except (filter(GetExceptionInformation())) {
        return 1;
    }
    printf("probe ok\n");
    return 0;
}
