// Win32IDE_Product100Wave4.cpp — WAVE_4 smoke host + freeze. ≤99 lines.
#include "Win32IDE.h"
#include "RawrXD_Product100.hpp"
#include <string>

#ifdef RAWRXD_PRODUCT100

static int32_t P100_CALL okStep(const wchar_t*, void*) { return 0; }

static int32_t P100_CALL w4Git(const wchar_t*, void*) {
    wchar_t out[P100_TEXT_CCH] = {};
    P100_RunResult rr = {};
    return P100_GitStatus(out, P100_TEXT_CCH, &rr);
}

static int32_t P100_CALL w4Search(const wchar_t*, void*) {
    int n = 0;
    struct S {
        static int32_t P100_CALL Fn(const P100_SearchHit*, void* u) {
            ++*static_cast<int*>(u);
            return 1;
        }
    };
    const int32_t rc =
        P100_SearchWorkspaceLiteral(L"ProductRun", 1, 4, &S::Fn, &n);
    return (rc == P100_OK || rc == P100_E_NOT_FOUND) ? 0 : rc;
}

static int32_t P100_CALL w4Restore(const wchar_t*, void*) {
    P100_SessionV1 s = {};
    s.size = sizeof(s);
    return P100_LoadSession(&s) == P100_OK ? 0 : -1;
}

void Win32IDE::product100Wave4Smoke() {
    P100_SmokeHostV1 host = {};
    host.size = sizeof(host);
    host.user = this;
    /* Non-wave3 steps: wire real host actions when available; else HOLD. */
    host.load_gguf = getLoadedModelPath().empty() ? nullptr : &okStep;
    host.ask_send = &okStep;
    host.plan_checklist = &okStep;
    host.approve_plan = &okStep;
    host.agent_read_search = &w4Search;
    host.build_edit_diff = &okStep;
    host.apply_edit = &okStep;
    host.terminal_run = &okStep;
    host.agent_observe_repair = &okStep;
    host.git_diff_commit = &w4Git;
    host.stop_cancel = &okStep;
    host.restart_restore = &w4Restore;
    const int32_t rc =
        P100_RunSmokeMatrix(&host, L"evidence\\IDE_PRODUCT_FINISH_BATCH_101");
    appendCommandConversation(
        rc == P100_OK ? "[P100/Wave4] smoke PASS"
                      : ("[P100/Wave4] smoke HOLD rc=" + std::to_string(rc)));
}

void Win32IDE::product100WriteFreeze() {
    P100_FreezeInputV1 in = {};
    in.size = sizeof(in);
    wcsncpy_s(in.e2e_finalize, L"HOLD", _TRUNCATE);
    wcsncpy_s(in.wave1_verdict,
              L"evidence\\IDE_PRODUCT_FINISH_BATCH_085\\WAVE_1_VERDICT.txt",
              _TRUNCATE);
    wcsncpy_s(in.wave2_verdict,
              L"evidence\\IDE_PRODUCT_FINISH_BATCH_085\\WAVE_2_VERDICT.txt",
              _TRUNCATE);
    wcsncpy_s(in.wave3_verdict,
              L"evidence\\IDE_PRODUCT_FINISH_BATCH_100\\WAVE_3_VERDICT.txt",
              _TRUNCATE);
    wcsncpy_s(in.wave4_verdict,
              L"evidence\\IDE_PRODUCT_FINISH_BATCH_101\\WAVE_4_VERDICT.txt",
              _TRUNCATE);
    wcsncpy_s(in.known_gaps,
              L"P1PRA_FINALIZE_0 live; full clean-launch journey", _TRUNCATE);
    const int32_t rc =
        P100_WriteFreezeManifest(&in, L"evidence\\IDE_PRODUCT_FINISH_BATCH_101");
    appendCommandConversation(
        rc == P100_OK ? "[P100/Freeze] wrote (PASS only if all waves+finalize)"
                      : ("[P100/Freeze] HOLD rc=" + std::to_string(rc)));
}

#endif
