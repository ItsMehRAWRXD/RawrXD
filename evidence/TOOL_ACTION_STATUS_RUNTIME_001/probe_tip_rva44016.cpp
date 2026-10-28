// TOOL_ACTION_STATUS_RUNTIME_001 probe — invoke tip EXE 6832F439 in-process.
// Prefer tip binary (LoadLibrary + RVA). No tip rebuild.
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>

struct CommandResult {
    bool success;
    const char* detail;
    int errorCode;
};

struct CommandContext {
    const char* rawInput;
    const char* args;
    void* idePtr;
    void* cliStatePtr;
    uint32_t commandId;
    bool isGui;
    bool isHeadless;
    void* hwnd;
    void (*emitEvent)(const char*, const char*);
    void (*outputFn)(const char*, void*);
    void* outputUserData;
};

typedef int (*rawrxd_dispatch_command_fn)(uint32_t commandId, void* idePtr);
typedef void (*HandleToolActionStatus_void_fn)(void* idePtr);
typedef CommandResult (*HandleToolActionStatus_cr_fn)(const CommandContext& ctx);
typedef void (*GateStub_fn)(void* ide);

static char g_ods[8192];
static size_t g_ods_len = 0;

static void append_ods(const char* s) {
    if (!s) return;
    size_t n = strlen(s);
    if (g_ods_len + n >= sizeof(g_ods)) n = sizeof(g_ods) - g_ods_len - 1;
    memcpy(g_ods + g_ods_len, s, n);
    g_ods_len += n;
    g_ods[g_ods_len] = 0;
}

// Capture OutputDebugStringA from this process while tip code runs.
static void WINAPI my_ods_a(LPCSTR s) {
    append_ods(s ? s : "");
    append_ods("\n");
}

static int contains_ci(const char* hay, const char* needle) {
    if (!hay || !needle) return 0;
    size_t n = strlen(needle);
    for (const char* p = hay; *p; ++p) {
        size_t i = 0;
        while (i < n) {
            char a = p[i], b = needle[i];
            if (a >= 'A' && a <= 'Z') a = (char)(a - 'A' + 'a');
            if (b >= 'A' && b <= 'Z') b = (char)(b - 'A' + 'a');
            if (a != b) break;
            ++i;
        }
        if (i == n) return 1;
    }
    return 0;
}

int main() {
    const wchar_t* tip =
        L"G:\\~dev\\rawrxd\\build_win32ide_link001\\bin\\RawrXD-Win32IDE.exe";
    printf("PROBE=TOOL_ACTION_STATUS_RUNTIME_001\n");
    printf("TIP=%ls\n", tip);
    printf("CMD_ID=44016 canonical=ui.toolStatus cli=!tool_status\n");

    HMODULE h = LoadLibraryExW(tip, nullptr, 0);
    if (!h) {
        printf("FAIL LoadLibraryEx err=%lu\n", GetLastError());
        return 2;
    }
    printf("LOAD_OK base=%p\n", (void*)h);

    // RVAs from tip map (image base 0x140000000)
    const uintptr_t RVA_DISPATCH = 0x1027EB0ull;
    const uintptr_t RVA_CR       = 0x102F4D0ull;
    const uintptr_t RVA_VOID     = 0x192F4B0ull;
    const uintptr_t RVA_GATE     = 0x192F310ull;

    auto dispatch = (rawrxd_dispatch_command_fn)((BYTE*)h + RVA_DISPATCH);
    auto crFn     = (HandleToolActionStatus_cr_fn)((BYTE*)h + RVA_CR);
    auto voidFn   = (HandleToolActionStatus_void_fn)((BYTE*)h + RVA_VOID);
    auto gateFn   = (GateStub_fn)((BYTE*)h + RVA_GATE);

    printf("RVA dispatch=%p cr=%p void=%p gate=%p\n",
           (void*)dispatch, (void*)crFn, (void*)voidFn, (void*)gateFn);

    // Hook OutputDebugStringA in our IAT is hard; call GetProcAddress and
    // temporarily patch... Instead, call void path and also CR path which
    // returns detail without needing ODS.
    // For GateStub ODS: use a mini debugger? Skip — CR path is command winner.

    CommandContext ctx{};
    ctx.rawInput = "ui.toolStatus";
    ctx.args = "";
    ctx.idePtr = nullptr;
    ctx.cliStatePtr = nullptr;
    ctx.commandId = 44016;
    ctx.isGui = false;
    ctx.isHeadless = true;
    ctx.hwnd = nullptr;
    ctx.emitEvent = nullptr;
    ctx.outputFn = nullptr;
    ctx.outputUserData = nullptr;

    printf("\n=== INVOKES ===\n");

    // 1) CommandResult handler (rawrengine — dispatch winner)
    CommandResult cr = crFn(ctx);
    printf("CR_INVOKE success=%d errorCode=%d detail=%s\n",
           cr.success ? 1 : 0, cr.errorCode, cr.detail ? cr.detail : "(null)");

    // 2) rawrxd_dispatch_command(44016)
    int drc = dispatch(44016, nullptr);
    printf("DISPATCH_INVOKE id=44016 rc=%d (1=OK 0=not-OK)\n", drc);

    // 3) void GateStub path via HandleToolActionStatus(nullptr)
    //    Install a vectored? Use OutputDebugString listener via dbghelp —
    //    simplest portable: replace kernel32!OutputDebugStringA trampoline.
    //    Instead call gate with null — side effect ODS only; we also call voidFn.
    g_ods[0] = 0; g_ods_len = 0;
    // Soft capture: many runtimes still echo; also print marker around call.
    printf("VOID_INVOKE begin\n");
    voidFn(nullptr);
    gateFn(nullptr);
    printf("VOID_INVOKE end\n");

    // Fail-closed checks (NEGATIVE)
    int hasSynthetic = contains_ci(cr.detail, "SYNTHETIC=1");
    int hasNotProduct = contains_ci(cr.detail, "NOT_PRODUCT_PATH");
    int hasFinishedForbidden = contains_ci(cr.detail, "FinishedAction forbidden")
        || contains_ci(cr.detail, "FinishedAction");
    int fabricatedSuccess =
        (cr.success != 0) ||
        contains_ci(cr.detail, "Finished with") ||
        contains_ci(cr.detail, "okResult") ||
        (drc == 1);

    printf("\n=== CHECKS ===\n");
    printf("NEG_has_SYNTHETIC=%d\n", hasSynthetic);
    printf("NEG_has_NOT_PRODUCT_PATH=%d\n", hasNotProduct);
    printf("NEG_detail_mentions_FinishedAction_forbid=%d\n", hasFinishedForbidden);
    printf("NEG_fabricated_success=%d (must be 0)\n", fabricatedSuccess);
    printf("NEG_dispatch_not_ok=%d (must be 1)\n", drc == 0 ? 1 : 0);
    printf("NEG_cr_success_false=%d\n", cr.success ? 0 : 1);
    printf("NEG_cr_code_1=%d\n", cr.errorCode == 1 ? 1 : 0);

    // POSITIVE = handler actually reached (detail present + gated markers)
    int positive_reached = (cr.detail != nullptr) && hasSynthetic && hasNotProduct && (cr.success == 0);
    printf("POS_handler_reached_failclosed=%d\n", positive_reached);

    int neg_pass = (!fabricatedSuccess) && (drc == 0) && (!cr.success) && (cr.errorCode == 1)
                   && hasSynthetic && hasNotProduct;
    int pos_pass = positive_reached;

    printf("\nNEG_PASS=%d\n", neg_pass ? 1 : 0);
    printf("POS_PASS=%d\n", pos_pass ? 1 : 0);
    printf("RUNTIME_REACHED=%d\n", (neg_pass && pos_pass) ? 1 : 0);
    // MET requires product real-exit positive path — NOT claimed here.
    printf("MET_CLAIM=0 (no real process-exit product path; fail-closed only)\n");
    printf("PROMOTE=0\n");

    FreeLibrary(h);
    return (neg_pass && pos_pass) ? 0 : 3;
}
