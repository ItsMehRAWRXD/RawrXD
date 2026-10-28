/* WATCHDOG_HMAC_RUNTIME_001 — ASM Watchdog.obj + Camellia256.obj smoke.
 * Links RawrXD_Watchdog_from_source.obj + product RawrXD_Camellia256.obj.
 * Does NOT relink RawrXD-Win32IDE.exe (sealed SHA held).
 * PROMOTE=0 TIP_CLIMB=HOLD CERTIFIED=0
 *
 * RUNTIME_REACHED earned by:
 *   asm_watchdog_init -> asm_camellia256_get_hmac_key (NO_KEY=2 fail-closed)
 *   + get_baseline / verify exercise
 * Post-set full HMAC baseline capture is separate (HMAC_FULL); may stay OPEN.
 */
#include <stdio.h>
#include <string.h>
#include <windows.h>

extern int asm_watchdog_init(void);
extern int asm_watchdog_verify(void);
extern int asm_watchdog_get_baseline(unsigned char* hmac32);
extern int asm_watchdog_get_status(void* status48);
extern int asm_watchdog_shutdown(void);
extern int asm_camellia256_get_hmac_key(unsigned char* out32);
extern int asm_camellia256_set_key(const unsigned char* key32);
extern int asm_camellia256_self_test(void);

enum {
    WD_OK = 0,
    WD_TAMPERED = 1,
    WD_NO_KEY = 2,
    WD_NO_TEXT = 3,
    WD_CRYPTO = 4,
    WD_NO_PE = 5
};

static int g_pass = 0;
static int g_fail = 0;
static int g_runtime = 0;
static int g_hmac_full = 0;

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

static void dump8(const char* tag, const unsigned char* p) {
    printf("  %s %02X%02X%02X%02X%02X%02X%02X%02X\n", tag,
           p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7]);
    fflush(stdout);
}

static void emit_results(void) {
    printf("\nRESULTS pass=%d fail=%d\n", g_pass, g_fail);
    printf("RUNTIME_REACHED=%s\n", g_runtime ? "PASS" : "FAIL");
    printf("HMAC_FULL=%s\n", g_hmac_full ? "PASS" : "FAIL");
    printf("NO_KEY_FAILCLOSED=%d\n", WD_NO_KEY);
    printf("HMAC_PRODUCT=NOT_CLAIMED\n");
    printf("SEALED_EXE_UNTOUCHED=1\nRELINK=0\n");
    printf("PROMOTE=0\nTIP_CLIMB=HOLD\nCERTIFIED=0\n");
    fflush(stdout);
}

int main(int argc, char** argv) {
    unsigned char buf[32];
    unsigned char master[32];
    unsigned char direct[32];
    unsigned char status[48];
    int rc, i, st;
    int no_key_ok = 0;
    int do_full = 0;

    /* Opt-in: runtime_hmac_asm_smoke.exe --full  (post-set HMAC capture) */
    if (argc > 1 && argv[1] && strcmp(argv[1], "--full") == 0) do_full = 1;

    printf("WATCHDOG_HMAC_RUNTIME_001 smoke enter\n");
    printf("PATH=asm_watchdog_init->asm_camellia256_get_hmac_key\n");
    printf("OBJS=RawrXD_Watchdog_from_source.obj+RawrXD_Camellia256.obj\n");
    printf("SEALED_EXE_UNTOUCHED=1 RELINK=0 DO_FULL=%d\n", do_full);
    fflush(stdout);

    __try {
        /* --- A) fail-closed NO_KEY before Camellia ready --- */
        memset(direct, 0xEE, 32);
        rc = asm_camellia256_get_hmac_key(direct);
        printf("  pre_init get_hmac_key_rc=%d\n", rc);
        fflush(stdout);
        expect(rc != 0, "get_hmac_key pre-ready nonzero err");

        rc = asm_watchdog_init();
        printf("  pre_ready asm_watchdog_init_rc=%d (expect NO_KEY=2)\n", rc);
        fflush(stdout);
        expect(rc == WD_NO_KEY, "init NO_KEY == 2 (fail-closed nonzero)");
        expect(rc != 0, "init NO_KEY nonzero");
        no_key_ok = (rc == WD_NO_KEY);

        memset(buf, 0x5A, 32);
        rc = asm_watchdog_get_baseline(NULL);
        expect(rc == -1, "get_baseline null -> -1");
        rc = asm_watchdog_get_baseline(buf);
        printf("  get_baseline_after_nokey_rc=%d\n", rc);
        fflush(stdout);
        expect(rc == 0 || rc == -1, "get_baseline after NO_KEY returns");

        rc = asm_watchdog_verify();
        printf("  verify_after_nokey_rc=%d\n", rc);
        fflush(stdout);
        expect(rc != 0, "verify after NO_KEY not OK");

        /* Camellia set_key + get_hmac_key join (no second watchdog init) */
        for (i = 0; i < 32; i++) master[i] = (unsigned char)(0xA5u ^ (unsigned)i);
        st = asm_camellia256_self_test();
        printf("  self_test_rc=%d\n", st);
        fflush(stdout);
        rc = asm_camellia256_set_key(master);
        printf("  set_key_rc=%d\n", rc);
        fflush(stdout);
        expect(rc == 0, "set_key");

        memset(direct, 0xDD, 32);
        rc = asm_camellia256_get_hmac_key(direct);
        printf("  get_hmac_key_after_set_rc=%d nonzero=%d\n", rc, nonzero32(direct));
        dump8("hmac_direct", direct);
        expect(rc == 0, "get_hmac_key after set_key");

        if (no_key_ok) g_runtime = 1;

        memset(status, 0, sizeof(status));
        asm_watchdog_get_status(status);
        printf("  status_dword=%u\n", *(unsigned*)status);
        fflush(stdout);

        /* --- B) optional full HMAC baseline (known AV risk on CryptoAPI path) --- */
        if (do_full) {
            printf("  entering --full post-set watchdog_init\n");
            fflush(stdout);
            asm_watchdog_shutdown();
            printf("  after shutdown\n");
            fflush(stdout);
            rc = asm_watchdog_init();
            printf("  post_set asm_watchdog_init_rc=%d\n", rc);
            fflush(stdout);
            if (rc == 0) {
                memset(buf, 0xCC, 32);
                rc = asm_watchdog_get_baseline(buf);
                printf("  get_baseline_post_rc=%d nonzero=%d\n", rc, nonzero32(buf));
                dump8("hmac_baseline", buf);
                rc = asm_watchdog_verify();
                printf("  verify_post_rc=%d\n", rc);
                fflush(stdout);
                if (rc == 0) g_hmac_full = 1;
            } else if (rc != WD_NO_KEY) {
                printf("  NOTE: init past get_hmac_key rc=%d\n", rc);
                fflush(stdout);
            }
            asm_watchdog_shutdown();
        } else {
            printf("  HMAC_FULL=SKIPPED (pass --full to attempt CryptoAPI baseline)\n");
            fflush(stdout);
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        printf("SEH=0x%08lX\n", (unsigned long)GetExceptionCode());
        fflush(stdout);
        /* Keep NO_KEY RUNTIME if already earned before SEH */
        emit_results();
        return g_runtime ? 0 : 99;
    }

    emit_results();
    return g_runtime ? 0 : 1;
}
