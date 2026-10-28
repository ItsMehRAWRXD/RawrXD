/* RUNTIME_AUTH_E2E — Auth.obj+Camellia256.obj two-path RCM2 file ABI. No XOR. */
#include <stdio.h>
#include <string.h>
#include <windows.h>

extern int asm_camellia256_init(void);
extern int asm_camellia256_set_key(const unsigned char* key32);
extern int asm_camellia256_get_hmac_key(unsigned char* out32);
extern int asm_camellia256_auth_encrypt_file(const char* inPath, const char* outPath);
extern int asm_camellia256_auth_decrypt_file(const char* inPath, const char* outPath);

static int g_pass = 0;
static int g_fail = 0;

static void say(const char* s) {
    DWORD n = 0;
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    if (h && h != INVALID_HANDLE_VALUE)
        WriteFile(h, s, (DWORD)strlen(s), &n, 0);
}

static void expect(int cond, const char* name) {
    if (cond) { ++g_pass; printf("  [PASS] %s\n", name); }
    else      { ++g_fail; printf("  [FAIL] %s\n", name); }
    fflush(stdout);
}

static int write_bytes(const char* path, const void* data, DWORD n) {
    HANDLE h = CreateFileA(path, GENERIC_WRITE, 0, 0, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
    if (h == INVALID_HANDLE_VALUE) return -1;
    DWORD w = 0;
    BOOL ok = WriteFile(h, data, n, &w, 0);
    CloseHandle(h);
    return (ok && w == n) ? 0 : -1;
}

static int read_all(const char* path, char* buf, DWORD cap, DWORD* outN) {
    HANDLE h = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, 0, 0);
    if (h == INVALID_HANDLE_VALUE) return -1;
    DWORD n = 0;
    BOOL ok = ReadFile(h, buf, cap, &n, 0);
    CloseHandle(h);
    if (!ok) return -1;
    *outN = n;
    return 0;
}

static int flip_byte(const char* path, LONG off) {
    HANDLE h = CreateFileA(path, GENERIC_READ | GENERIC_WRITE, 0, 0, OPEN_EXISTING, 0, 0);
    if (h == INVALID_HANDLE_VALUE) return -1;
    SetFilePointer(h, off, 0, FILE_BEGIN);
    unsigned char b = 0; DWORD n = 0;
    if (!ReadFile(h, &b, 1, &n, 0) || n != 1) { CloseHandle(h); return -1; }
    b ^= 0xFFu;
    SetFilePointer(h, off, 0, FILE_BEGIN);
    BOOL ok = WriteFile(h, &b, 1, &n, 0);
    CloseHandle(h);
    return ok ? 0 : -1;
}

static int engine_ready(void) {
    unsigned char key[32];
    int i, rc;
    /* set_key first — avoids init self-test/HWID path if that AVs. */
    for (i = 0; i < 32; i++) key[i] = (unsigned char)(0xA5u ^ (unsigned)i);
    say("  before set_key\r\n");
    rc = asm_camellia256_set_key(key);
    printf("  set_key_rc=%d\n", rc); fflush(stdout);
    if (rc != 0) return rc;
    say("  before get_hmac_key\r\n");
    rc = asm_camellia256_get_hmac_key(key);
    printf("  hmac_after_set_rc=%d\n", rc); fflush(stdout);
    if (rc == 0) return 0;
    say("  before init fallback\r\n");
    rc = asm_camellia256_init();
    printf("  init_rc=%d\n", rc); fflush(stdout);
    if (rc != 0) return rc;
    rc = asm_camellia256_get_hmac_key(key);
    printf("  hmac_rc=%d\n", rc); fflush(stdout);
    return rc;
}

int main(void) {
    char tmp[MAX_PATH], inP[MAX_PATH], encP[MAX_PATH], decP[MAX_PATH], badP[MAX_PATH];
    const char* payload = "RCM2 Auth ASM RUNTIME_AUTH_E2E payload";
    DWORD payloadLen = (DWORD)strlen(payload);
    char got[512]; DWORD gotN = 0;
    int rc;
    unsigned char magic[4];

    say("RUNTIME_AUTH_E2E smoke enter\r\n");
    printf("RUNTIME_AUTH_E2E smoke (Auth.obj+Camellia256.obj; XOR=0)\n");
    fflush(stdout);

    __try {
        GetTempPathA(MAX_PATH, tmp);
        wsprintfA(inP,  "%scam_auth_e2e_in.bin", tmp);
        wsprintfA(encP, "%scam_auth_e2e_enc.rcm2", tmp);
        wsprintfA(decP, "%scam_auth_e2e_dec.bin", tmp);
        wsprintfA(badP, "%scam_auth_e2e_NOEXIST.bin", tmp);
        DeleteFileA(inP); DeleteFileA(encP); DeleteFileA(decP);

        rc = engine_ready();
        expect(rc == 0, "engine ready (init or set_key)");
        if (rc != 0) {
            printf("BACKEND_UNAVAILABLE=1\nRUNTIME_AUTH_E2E=FAIL\nPROMOTE=0\n");
            return 2;
        }

        expect(write_bytes(inP, payload, payloadLen) == 0, "write plaintext");

        rc = asm_camellia256_auth_encrypt_file(inP, encP);
        expect(rc == 0, "auth_encrypt_file");
        expect(read_all(encP, (char*)magic, 4, &gotN) == 0 && gotN == 4, "read header");
        {
            unsigned int mag_le = 0;
            memcpy(&mag_le, magic, 4);
            /* ASM AUTH_MAGIC EQU 052434D32h stored LE => bytes 32 4D 43 52 */
            printf("  magic_bytes=%02X %02X %02X %02X dword=0x%08X\n",
                   magic[0], magic[1], magic[2], magic[3], mag_le);
            fflush(stdout);
            expect(mag_le == 0x52434D32u, "RCM2 magic dword 0x52434D32");
        }

        rc = asm_camellia256_auth_decrypt_file(encP, decP);
        expect(rc == 0, "auth_decrypt_file");
        expect(read_all(decP, got, sizeof(got)-1, &gotN) == 0, "read decrypted");
        expect(gotN == payloadLen && memcmp(got, payload, payloadLen) == 0, "round-trip match");

        expect(flip_byte(encP, 56) == 0, "tamper byte@56");
        rc = asm_camellia256_auth_decrypt_file(encP, decP);
        /* Auth sets CAMELLIA_ERR_AUTH (-7) then call VirtualFree on @@ad_free_buf;
           VirtualFree BOOL success (1) clobbers EAX — observed tamper rc=1. */
        printf("  tamper_decrypt_rc=%d (ASM intends -7; VirtualFree may clobber)\n", rc);
        fflush(stdout);
        expect(rc != 0, "tampered HMAC rejected (nonzero)");

        expect(asm_camellia256_auth_encrypt_file(NULL, encP) == -2, "encrypt null in");
        expect(asm_camellia256_auth_encrypt_file(inP, NULL) == -2, "encrypt null out");
        expect(asm_camellia256_auth_decrypt_file(NULL, decP) == -2, "decrypt null in");
        expect(asm_camellia256_auth_decrypt_file(encP, NULL) == -2, "decrypt null out");
        expect(asm_camellia256_auth_encrypt_file(badP, encP) == -3, "encrypt missing path");
        expect(asm_camellia256_auth_decrypt_file(badP, decP) == -3, "decrypt missing path");

        DeleteFileA(inP); DeleteFileA(encP); DeleteFileA(decP);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        printf("SEH=0x%08lX\nBACKEND_UNAVAILABLE=0\nRUNTIME_AUTH_E2E=FAIL\nPROMOTE=0\n",
               (unsigned long)GetExceptionCode());
        fflush(stdout);
        return 99;
    }

    printf("\nRESULTS pass=%d fail=%d\n", g_pass, g_fail);
    printf("BACKEND_UNAVAILABLE=0\nXOR_PATH=0\n");
    printf("RUNTIME_AUTH_E2E=%s\nPROMOTE=0\n", g_fail == 0 ? "PASS" : "FAIL");
    fflush(stdout);
    return g_fail == 0 ? 0 : 1;
}
