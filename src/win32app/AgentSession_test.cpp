#include "AgentSession.hpp"
#include <cstdio>
#include <string>

static int g_fail = 0;
static void Expect(bool ok, const char* m) {
    if (!ok) { std::printf("FAIL %s\n", m); ++g_fail; }
}

int main() {
    const char* dir = "agent_session_unit";
    uint64_t sid = 0, tid = 0;
    Expect(AgentSessionBegin(dir, &sid, &tid), "begin");
    Expect(sid != 0 && tid != 0, "ids");
    AgentSessionNoteWrite("a.txt", "", "hello");
    Expect(AgentSessionFilesChanged() == 1, "one edit");
    AgentSessionNoteWrite("a.txt", "hello", "");
    Expect(AgentSessionFilesChanged() == 0, "reverted");
    AgentSessionNoteWrite("b.txt", "", "x");
    AgentSessionNoteWrite("c.txt", "old", "new");
    Expect(AgentSessionFilesChanged() == 2, "two edits");
    AgentSessionNoteTerminal(7, 1);
    Expect(AgentSessionTerminals() == 1, "terminal live");
    AgentSessionNoteTerminal(7, 0);
    Expect(AgentSessionTerminals() == 0, "terminal closed");
    uint64_t saved = sid;
    AgentSessionAbandonLive();
    Expect(AgentSessionFilesChanged() == 0, "abandoned");
    AgentSessionNote note{};
    Expect(AgentSessionRestore(dir, &note), "restore");
    Expect(note.sessionId == saved, "same session");
    Expect(note.filesChanged == 2, "restored count");
    Expect(note.terminals == 0, "no live process after restore");
    Expect(AgentSessionRestore(dir, &note), "restore twice");
    Expect(note.filesChanged == 2, "restore is stable");
    AgentSessionCancel();
    Expect(AgentSessionCancelled(), "cancel");
    std::printf("AGENT_SESSION_UNIT failures=%d\n", g_fail);
    return g_fail ? 1 : 0;
}
