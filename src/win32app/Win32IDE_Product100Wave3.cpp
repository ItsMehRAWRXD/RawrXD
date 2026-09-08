// Win32IDE_Product100Wave3.cpp — Wave3 session/settings/approval/smoke.
#include "Win32IDE.h"
#include "RawrXD_Product100.hpp"
#include "Win32Utf8.hpp"
#include "../command/CommandBroker.h"
#include <filesystem>
#include <string>

#ifdef RAWRXD_PRODUCT100

static std::wstring w8(const std::string& s) {
    return s.empty() ? std::wstring() : RawrXD::Utf8ToWide(s);
}

void Win32IDE::product100SaveSessionNow() {
    P100_SessionV1 session = {};
    session.size = sizeof(session);
    const std::string ws = m_gitRepoPath.empty()
                               ? std::filesystem::current_path().string()
                               : m_gitRepoPath;
    wcsncpy_s(session.workspace, w8(ws).c_str(), _TRUNCATE);
    wcsncpy_s(session.model_path, w8(getLoadedModelPath()).c_str(), _TRUNCATE);
    const char* ml = RawrXD::Command::CommandBroker::steerModeLabel(
        RawrXD::Command::CommandBroker::instance().steerMode());
    wcsncpy_s(session.mode, w8(ml ? ml : "Agent").c_str(), _TRUNCATE);
    const int32_t rc = P100_SaveSession(&session);
    appendCommandConversation(rc == P100_OK ? "[P100/Session] saved"
                                            : product100DescribeError(rc, "session"));
}

void Win32IDE::product100ShowSettings() {
    P100_SettingsV1 s = {};
    s.size = sizeof(s);
    if (P100_LoadSettings(&s) != P100_OK) {
        appendCommandConversation("[P100/Settings] load FAIL");
        return;
    }
    appendCommandConversation(
        "[P100/Settings] ctx=" + std::to_string(s.context_tokens) +
        " temp=" + std::to_string(s.temperature) +
        " model=" + RawrXD::WideToUtf8(std::wstring(s.model_path)));
}

void Win32IDE::product100ListApprovals() {
    P100_ApprovalV1 items[16] = {};
    uint32_t n = 0;
    if (P100_ListApprovals(items, 16, &n) != P100_OK) {
        appendCommandConversation("[P100/Approval] list FAIL");
        return;
    }
    appendCommandConversation("[P100/Approval] count=" + std::to_string(n));
    for (uint32_t i = 0; i < n && i < 16; ++i)
        appendCommandConversation(
            "  id=" + std::to_string(items[i].id) +
            " state=" + std::to_string(items[i].state) + " " +
            RawrXD::WideToUtf8(std::wstring(items[i].verb)));
}

static int32_t P100_CALL w3Git(const wchar_t*, void*) {
    wchar_t out[P100_TEXT_CCH] = {};
    P100_RunResult rr = {};
    return P100_GitStatus(out, P100_TEXT_CCH, &rr);
}
static int32_t P100_CALL w3Search(const wchar_t*, void*) {
    int n = 0;
    struct S {
        static int32_t P100_CALL Fn(const P100_SearchHit*, void* u) {
            ++*static_cast<int*>(u);
            return 1;
        }
    };
    const int32_t rc = P100_SearchWorkspaceLiteral(L"ProductRun", 1, 8, &S::Fn, &n);
    return (rc == P100_OK || rc == P100_E_NOT_FOUND) ? 0 : rc;
}
static int32_t P100_CALL w3Restore(const wchar_t*, void*) {
    P100_SessionV1 s = {};
    s.size = sizeof(s);
    return P100_LoadSession(&s) == P100_OK ? 0 : -1;
}

void Win32IDE::product100Wave3Smoke() {
    P100_SmokeHostV1 host = {};
    host.size = sizeof(host);
    host.user = this;
    host.agent_read_search = &w3Search;
    host.git_diff_commit = &w3Git;
    host.restart_restore = &w3Restore;
    const int32_t rc =
        P100_RunSmokeMatrix(&host, L"evidence\\IDE_PRODUCT_FINISH_BATCH_100");
    appendCommandConversation(
        rc == P100_OK ? "[P100/Wave3] smoke PASS (wave3 wired; full may HOLD)"
                      : ("[P100/Wave3] smoke HOLD rc=" + std::to_string(rc)));
}

#endif
