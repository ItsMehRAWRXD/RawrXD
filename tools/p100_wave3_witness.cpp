/* p100_wave3_witness — headless Product100 Wave3 API cert. ≤99 lines. */
#include "RawrXD_Product100.hpp"
#include <cstdio>
#include <string>

static int32_t P100_CALL hit(const P100_SearchHit*, void* u) {
    ++*static_cast<int*>(u);
    return 1;
}

static int rein(P100_Context& ctx, const wchar_t* ws) {
    P100_Shutdown();
    wcsncpy_s(ctx.workspace, ws, _TRUNCATE);
    return P100_Init(&ctx) == P100_OK ? 1 : 0;
}

int main() {
    const wchar_t* repo = L"g:\\~dev\\rawrxd";
    const wchar_t* tiny = L"g:\\~dev\\rawrxd\\src\\deep2\\lavapath";
    P100_Context ctx = {};
    ctx.size = sizeof(ctx);
    wcsncpy_s(ctx.workspace, repo, _TRUNCATE);
    wcsncpy_s(ctx.evidence_dir,
              L"g:\\~dev\\rawrxd\\evidence\\IDE_PRODUCT_FINISH_BATCH_100",
              _TRUNCATE);
    ctx.capabilities = P100_CAP_READ | P100_CAP_SEARCH | P100_CAP_GIT_READ |
                       P100_CAP_SETTINGS | P100_CAP_PERSISTENCE |
                       P100_CAP_GIT_WRITE | P100_CAP_COMMAND;
    if (P100_Init(&ctx) != P100_OK) {
        std::printf("P100_INIT=0\n");
        return 1;
    }
    wchar_t out[P100_TEXT_CCH] = {};
    P100_RunResult rr = {};
    const int gitOk = P100_GitStatus(out, P100_TEXT_CCH, &rr) == P100_OK;
    const int diffOk = P100_GitDiff(out, P100_TEXT_CCH, &rr) == P100_OK;
    if (!rein(ctx, tiny)) {
        std::printf("P100_INIT=0\n");
        return 1;
    }
    int hits = 0;
    const int searchRc =
        P100_SearchWorkspaceLiteral(L"ProductRun", 1, 4, &hit, &hits);
    const int searchOk =
        (searchRc == P100_OK || searchRc == P100_E_NOT_FOUND);
    P100_SettingsV1 s = {};
    s.size = sizeof(s);
    s.context_tokens = 4096;
    const int setOk = P100_SaveSettings(&s) == P100_OK &&
                      P100_LoadSettings(&s) == P100_OK;
    P100_SessionV1 sess = {};
    sess.size = sizeof(sess);
    wcsncpy_s(sess.workspace, repo, _TRUNCATE);
    wcsncpy_s(sess.mode, L"Agent", _TRUNCATE);
    const int sessOk = P100_SaveSession(&sess) == P100_OK &&
                       P100_LoadSession(&sess) == P100_OK;
    P100_ApprovalV1 ap = {};
    ap.size = sizeof(ap);
    ap.required_capabilities = P100_CAP_GIT_WRITE;
    wcsncpy_s(ap.verb, L"git_write", _TRUNCATE);
    uint64_t id = 0;
    const int apOk = P100_AddApproval(&ap, &id) == P100_OK &&
                     P100_DecideApproval(id, 1) == P100_OK;
    std::printf("WAVE3_GIT_STATUS=%d\nWAVE3_GIT_DIFF=%d\nWAVE3_SEARCH=%d\n"
                "WAVE3_SETTINGS=%d\nWAVE3_SESSION=%d\nWAVE3_APPROVAL=%d\n",
                gitOk, diffOk, searchOk, setOk, sessOk, apOk);
    const int pass = gitOk && diffOk && searchOk && setOk && sessOk && apOk;
    std::printf("WAVE3_API_PASS=%d\n", pass);
    P100_Shutdown();
    return pass ? 0 : 2;
}
