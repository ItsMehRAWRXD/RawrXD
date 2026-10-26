#include "IdeAuthBoundary.hpp"
#include "AgentProduct.hpp"
#include <cstdio>
#include <cstdlib>
#include <string>
#include <windows.h>

static int g_fail = 0;

static void Expect(bool cond, const char* name) {
    std::printf("%s %s\n", cond ? "ok" : "FAIL", name);
    if (!cond) ++g_fail;
}

int main() {
    char tmp[MAX_PATH] = {};
    GetTempPathA(MAX_PATH, tmp);
    const std::string root = std::string(tmp) + "rawr_ide_auth_root";
    const std::string outside = std::string(tmp) + "rawr_ide_auth_out";
    CreateDirectoryA(root.c_str(), nullptr);
    CreateDirectoryA(outside.c_str(), nullptr);
    const std::string inside = root + "\\inside.txt";
    HANDLE h = CreateFileA(inside.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                           FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h != INVALID_HANDLE_VALUE) CloseHandle(h);
    const std::string link = root + "\\jmp";
    const std::string mk = "cmd /c mklink /J \"" + link + "\" \"" + outside + "\" >nul 2>&1";
    std::system(mk.c_str());

    RawrXD::IdeAuth::SetWorkspaceRoot(root);
    RawrXD::IdeAuth::SetListenPort(11435);
    std::string canon, err;
    Expect(RawrXD::IdeAuth::CanonicalInsideWorkspace("inside.txt", canon, err), "relative-inside");
    Expect(!RawrXD::IdeAuth::CanonicalInsideWorkspace("C:\\Windows\\notepad.exe", canon, err),
           "drive-absolute-outside");
    Expect(!RawrXD::IdeAuth::CanonicalInsideWorkspace(root + "\\..\\outside.txt", canon, err),
           "dotdot");
    Expect(!RawrXD::IdeAuth::CanonicalInsideWorkspace("\\\\localhost\\c$\\Windows", canon, err),
           "unc");
    const DWORD linkAttr = GetFileAttributesA(link.c_str());
    if (linkAttr != INVALID_FILE_ATTRIBUTES && (linkAttr & FILE_ATTRIBUTE_REPARSE_POINT)) {
        Expect(!RawrXD::IdeAuth::CanonicalInsideWorkspace(link + "\\secret.txt", canon, err),
               "junction-escape");
    } else {
        std::printf("SKIP junction-escape mklink_unavailable\n");
        ++g_fail;
    }
    Expect(!RawrXD::IdeAuth::OriginAllowed("null"), "origin-null");
    Expect(!RawrXD::IdeAuth::OriginAllowed("https://evil.example"), "origin-evil");
    Expect(RawrXD::IdeAuth::OriginAllowed("http://127.0.0.1:11435"), "origin-loopback");
    const auto noSession = RawrXD::IdeAuth::DecideWin32(
        "POST", "/api/debug/attach", "", "{\"pid\":4}");
    Expect(noSession == RawrXD::IdeAuth::HttpDecision::Unauthorized, "debug-without-session");
    SetEnvironmentVariableA("RAWRXD_IDE_EXEC_GRANT", "");
    const std::string hdr = std::string("X-RawrXD-Session: ") +
                            RawrXD::IdeAuth::SessionToken() + "\r\n";
    const auto noGrant = RawrXD::IdeAuth::DecideWin32(
        "POST", "/api/debug/attach", hdr, "{\"pid\":4}");
    Expect(noGrant == RawrXD::IdeAuth::HttpDecision::ExecDenied, "debug-without-exec-grant");
    const auto readOk = RawrXD::IdeAuth::DecideWin32(
        "POST", "/api/tool", hdr, "{\"tool\":\"read_file\"}");
    Expect(readOk == RawrXD::IdeAuth::HttpDecision::Allow, "read-with-session");
    const std::string evil = "Origin: https://evil.example\r\n" + hdr;
    const auto evilDecision = RawrXD::IdeAuth::DecideWin32("POST", "/api/tool", evil, "{}");
    Expect(evilDecision == RawrXD::IdeAuth::HttpDecision::ForbiddenOrigin, "evil-origin");
    std::vector<AgentToolCall> calls;
    Expect(AgentParseToolCalls(
        "{\"tool_calls\":[{\"name\":\"read_file\",\"arguments\":{\"path\":\"inside.txt\"}}]}",
        calls) && calls.size() == 1 && calls[0].name == "read_file", "structured-tool-call");
    calls.clear();
    Expect(!AgentParseToolCalls("tool:read_file path=inside.txt", calls), "substring-tool-ignored");
    std::printf("IDE_AUTH_BOUNDARY_UNIT=%s failures=%d\n", g_fail ? "FAIL" : "PASS_UNIT", g_fail);
    return g_fail ? 1 : 0;
}
