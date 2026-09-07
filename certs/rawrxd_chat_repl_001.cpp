// certs/rawrxd_chat_repl_001.cpp — U02 (session multi-turn persistence)
#include "../src/cli/rawr_session_store.hpp"
#include <cstdio>
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif
int main() {
    rawr::SessionState s{};
    s.id = "chat_repl_001";
    s.modelAlias = "tinyllama";
    s.workspace = "G:\\~dev\\rawrxd";
    s.history.push_back({"user", "hello"});
    s.history.push_back({"assistant", "hi there"});
    s.history.push_back({"user", "remember me"});
    if (!rawr::SaveSession(s)) {
        puts("RAWRXD_CHAT_REPL_001=FAIL");
        return 1;
    }
    rawr::SessionState t{};
    if (!rawr::LoadSession(s.id, t) || t.history.size() != 3) {
        puts("RAWRXD_CHAT_REPL_001=FAIL");
        return 1;
    }
    if (t.history[2].content != "remember me") {
        puts("RAWRXD_CHAT_REPL_001=FAIL");
        return 1;
    }
#ifdef _WIN32
    CreateDirectoryA("G:\\~dev\\rawrxd\\evidence", nullptr);
    CreateDirectoryA("G:\\~dev\\rawrxd\\evidence\\RAWRXD_CHAT_REPL_001",
                     nullptr);
    FILE* gf = nullptr;
    fopen_s(&gf, "G:\\~dev\\rawrxd\\evidence\\RAWRXD_CHAT_REPL_001\\GATE.txt",
            "w");
    if (gf) {
        fprintf(gf, "RAWRXD_CHAT_REPL_001=PASS\n");
        fclose(gf);
    }
#endif
    puts("RAWRXD_CHAT_REPL_001=PASS");
    return 0;
}
