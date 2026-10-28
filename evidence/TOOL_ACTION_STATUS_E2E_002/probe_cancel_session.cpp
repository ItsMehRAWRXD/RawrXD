// AgentSession cancel: active cancel cannot later report success.
#include "../../src/win32app/AgentSession.hpp"
#include "../../src/win32app/AgentProduct.hpp"
#include "../../src/win32app/IdeAuthBoundary.hpp"
#include <cstdio>
#include <thread>
#include <windows.h>

int main() {
    std::printf("PROBE=TOOL_ACTION_STATUS_E2E_002_CANCEL\n");
    CreateDirectoryA(
        "g:\\~dev\\rawrxd\\evidence\\TOOL_ACTION_STATUS_E2E_002\\cancel_work", nullptr);
    RawrXD::IdeAuth::SetWorkspaceRoot(
        "g:\\~dev\\rawrxd\\evidence\\TOOL_ACTION_STATUS_E2E_002\\cancel_work");
    uint64_t sid = 0, tid = 0;
    if (!AgentSessionBegin(
            "g:\\~dev\\rawrxd\\evidence\\TOOL_ACTION_STATUS_E2E_002\\cancel_work",
            &sid, &tid)) {
        std::printf("CASE cancel_begin FAIL\n");
        return 1;
    }
    _putenv("RAWRXD_IDE_EXEC_GRANT=1");
    std::thread([] {
        Sleep(200);
        AgentSessionCancel();
    }).detach();
    std::string out = AgentRunCommand(
        "execute_command", "{\"command\":\"ping -n 8 127.0.0.1\"}");
    bool cancelled = AgentSessionCancelled();
    bool noInvent = out.find("\"success\":true") == std::string::npos;
    std::printf("CANCELLED=%d OUT_LEN=%zu\n", cancelled ? 1 : 0, out.size());
    std::printf("OUT_SNIP=%.180s\n", out.c_str());
    std::printf("CASE cancel_active_op %s\n", cancelled ? "PASS" : "FAIL");
    std::printf("CASE cancel_no_invent_success %s\n", noInvent ? "PASS" : "FAIL");
    AgentSessionAbandonLive();
    return (cancelled && noInvent) ? 0 : 1;
}
