#include "AgentSession.hpp"
#include "AgentProduct.hpp"
#include "IdeAuthBoundary.hpp"
#include <cstdio>
#include <fstream>
#include <thread>
#include <windows.h>

static int Fail(const char* msg) {
    std::printf("AGENT_SESSION_PROOF FAIL %s\n", msg);
    return 1;
}

int AgentSessionProductProof() {
    CreateDirectoryA("agent_session_proof", nullptr);
    RawrXD::IdeAuth::SetWorkspaceRoot("agent_session_proof");
    uint64_t sid = 0, tid = 0;
    if (!AgentSessionBegin("agent_session_proof", &sid, &tid)) return Fail("begin");
    std::string wrote = AgentExecTool("write_file",
        "{\"path\":\"note.txt\",\"content\":\"hello\"}", nullptr);
    if (wrote.find("wrote") == std::string::npos) return Fail("write");
    if (AgentSessionFilesChanged() != 1) return Fail("count");
    AgentExecTool("write_file", "{\"path\":\"note.txt\",\"content\":\"\"}", nullptr);
    if (AgentSessionFilesChanged() != 0) return Fail("revert");
    AgentExecTool("write_file", "{\"path\":\"note.txt\",\"content\":\"kept\"}", nullptr);
    if (AgentSessionFilesChanged() != 1) return Fail("kept");
    if (AgentSessionReviewFirst().find("kept") == std::string::npos) return Fail("review");
    _putenv("RAWRXD_IDE_EXEC_GRANT=1");
    std::string echo = AgentRunCommand("execute_command",
        "{\"command\":\"echo session-proof\"}");
    if (echo.find("session-proof") == std::string::npos) return Fail("echo");
    if (AgentSessionTerminals() != 0) return Fail("terminal-closed");
    std::thread([] { Sleep(300); AgentSessionCancel(); }).detach();
    AgentRunCommand("execute_command", "{\"command\":\"ping -n 8 127.0.0.1\"}");
    if (!AgentSessionCancelled()) return Fail("stop");
    if (AgentSessionTerminals() != 0) return Fail("stop-terminal");
    AgentSessionAbandonLive();
    AgentSessionNote note{};
    if (!AgentSessionRestore("agent_session_proof", &note)) return Fail("restore");
    if (note.sessionId != sid || note.filesChanged != 1 || note.terminals != 0)
        return Fail("restore-values");
    { std::ofstream out("agent_session_proof\\session.jsonl", std::ios::app); out << "\n{\"kind\":\"Fil"; }
    AgentSessionAbandonLive();
    if (!AgentSessionRestore("agent_session_proof", &note) || note.filesChanged != 1)
        return Fail("truncated");
    std::printf("AGENT_SESSION_PROOF files=%d review=1 stop=1 restore=1 session=%llu\n",
                note.filesChanged, static_cast<unsigned long long>(note.sessionId));
    return 0;
}
