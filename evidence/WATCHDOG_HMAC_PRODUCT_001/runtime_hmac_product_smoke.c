/* RUNTIME_HMAC_PRODUCT — batch_005 get_baseline → Camellia256 get_hmac_key.
 * Object/link smoke only. Does NOT relink RawrXD-Win32IDE.exe (sealed SHA).
 * PROMOTE=0 TIP_CLIMB=HOLD CERTIFIED=0
 *
 * Gates (fail-closed, independent):
 *   RUNTIME_REACHED — wired C++ path exercised (NO_KEY + get_hmac_key join)
 *   HMAC_PRODUCT    — nonzero real key material round-trip (not CRC-as-HMAC)
 *
 * Known Camellia sibling: set_key sets cam_initialized but does NOT derive
 * cam_hmac_key (derive lives in init KDF). init blocked by self_test=-8 here.
 */
#include <stdio.h>
#include <string.h>
#include <windows.h>

extern int asm_watchdog_get_baseline(unsigned char* hmac32);
extern int asm_camellia256_get_hmac_key(unsigned char* out32);
extern int asm_camellia256_set_key(const unsigned char* key32);
extern int asm_camellia256_init(void);
extern int asm_camellia256_self_test(void);

static int g_pass = 0;
static int g_fail = 0;
static int g_runtime = 0; /* earned independently of HMAC_PRODUCT */
static int g_hmac_product = 0;

static void expect(int cond, const char* name) {
    if (cond) { ++g_pass; printf("  [PASS] %s\n", name); }
    else      { ++g_fail; printf("  [FAIL] %s\n", name); }
    fflush(stdout);
}

static int nonzero32(const unsigned char* p) {
    int i;
    for (i = 0; i < 32; i++) if (p[i] != 0) return 1;
    return 0;
}

/* CRC-as-HMAC theater shape: bytes[4..31] all zero. */
static int looks_like_crc_pad(const unsigned char* p) {
    int i;
    for (i = 4; i < 32; i++) if (p[i] != 0) return 0;
    return 1;
}

static void dump8(const char* tag, const unsigned char* p) {
    printf("  %s %02X%02X%02X%02X%02X%02X%02X%02X\n", tag,
           p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7]);
    fflush(stdout);
}

int main(void) {
    unsigned char buf[32];
    unsigned char direct[32];
    unsigned char master[32];
    int rc, i, st;
    int all_zero;
    int join_ok = 0;
    int key_nz = 0;

    printf("RUNTIME_HMAC_PRODUCT smoke enter\n");
    printf("PATH=asm_watchdog_get_baseline->asm_camellia256_get_hmac_key\n");
    printf("TU=unlinked_symbols_batch_005.cpp (fresh obj) + RawrXD_Camellia256.obj\n");
    fflush(stdout);

    __try {
        /* --- A) fail-closed NO_KEY before Camellia init --- */
        for (i = 0; i < 32; i++) buf[i] = 0x5Au;
        rc = asm_watchdog_get_baseline(NULL);
        expect(rc == -1, "get_baseline null -> -1");
        rc = asm_watchdog_get_baseline(buf);
        expect(rc == -1, "get_baseline NO_KEY -> -1");
        all_zero = 1;
        for (i = 0; i < 32; i++) if (buf[i] != 0) all_zero = 0;
        expect(all_zero == 1, "NO_KEY zeros buffer (no CRC-as-HMAC)");

        /* --- B) Camellia set_key (Auth-smoke style; avoids init HWID) --- */
        for (i = 0; i < 32; i++) master[i] = (unsigned char)(0xA5u ^ (unsigned)i);
        st = asm_camellia256_self_test();
        printf("  self_test_rc=%d\n", st); fflush(stdout);
        rc = asm_camellia256_set_key(master);
        printf("  set_key_rc=%d\n", rc); fflush(stdout);
        expect(rc == 0, "set_key");

        memset(direct, 0xDD, 32);
        rc = asm_camellia256_get_hmac_key(direct);
        printf("  get_hmac_key_rc=%d nonzero=%d\n", rc, nonzero32(direct));
        dump8("hmac_direct", direct);
        expect(rc == 0, "get_hmac_key after set_key");

        memset(buf, 0xCC, 32);
        rc = asm_watchdog_get_baseline(buf);
        printf("  get_baseline_rc=%d nonzero=%d\n", rc, nonzero32(buf));
        dump8("hmac_baseline", buf);
        expect(rc == 0, "get_baseline after set_key -> 0");
        expect(memcmp(buf, direct, 32) == 0, "baseline matches get_hmac_key (join)");
        join_ok = (rc == 0 && memcmp(buf, direct, 32) == 0);

        /* RUNTIME_REACHED earned if NO_KEY fail-closed + join executed */
        if (g_pass >= 5 && join_ok) g_runtime = 1;

        key_nz = nonzero32(direct);
        if (key_nz && !looks_like_crc_pad(direct) && join_ok) {
            expect(1, "nonzero non-CRC key material");
            g_hmac_product = 1;
        } else {
            expect(0, "nonzero non-CRC key material");
            printf("  NOTE: set_key does not derive cam_hmac_key (zeros); init KDF owns derive\n");
            fflush(stdout);
        }

        /* --- C) init attempt (document; do not invent PASS) --- */
        rc = asm_camellia256_init();
        printf("  init_rc=%d (self_test gate; -8=SELF_TEST)\n", rc);
        fflush(stdout);
        if (rc == 0) {
            memset(direct, 0xDD, 32);
            memset(buf, 0xCC, 32);
            rc = asm_camellia256_get_hmac_key(direct);
            asm_watchdog_get_baseline(buf);
            printf("  post_init ghk_rc=%d nz=%d match=%d\n",
                   rc, nonzero32(direct), memcmp(buf, direct, 32) == 0);
            dump8("hmac_post_init", direct);
            if (rc == 0 && nonzero32(direct) && !looks_like_crc_pad(direct)
                && memcmp(buf, direct, 32) == 0) {
                g_hmac_product = 1;
                printf("  [PASS] post-init real key round-trip\n");
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        printf("SEH=0x%08lX\nRUNTIME_REACHED=FAIL\nHMAC_PRODUCT=FAIL\nPROMOTE=0\n",
               (unsigned long)GetExceptionCode());
        fflush(stdout);
        return 99;
    }

    printf("\nRESULTS pass=%d fail=%d\n", g_pass, g_fail);
    printf("RUNTIME_REACHED=%s\n", g_runtime ? "PASS" : "FAIL");
    printf("HMAC_PRODUCT=%s\n", g_hmac_product ? "PASS" : "FAIL");
    printf("CRC_AS_HMAC=0\nNO_KEY_FAILCLOSED=-1\n");
    printf("CAM_HMAC_AFTER_SET_KEY=%s\n", key_nz ? "NONZERO" : "ZERO");
    printf("INIT_SELF_TEST_BLOCK=%d\n", st);
    printf("RELINK_REQUIRED=1\nSEALED_EXE_UNTOUCHED=1\n");
    printf("PROMOTE=0\nTIP_CLIMB=HOLD\nCERTIFIED=0\n");
    fflush(stdout);
    /* Exit 0 only if RUNTIME earned; HMAC_PRODUCT may still be FAIL. */
    return g_runtime ? 0 : 1;
}
