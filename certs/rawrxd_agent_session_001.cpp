#include "../src/cli/rawr_session_store.hpp"
#include <cstdio>
int main() {
    rawr::SessionState s{};
    s.id = "cert_sess_001";
    s.modelAlias = "tinyllama";
    s.workspace = "G:\\~dev\\rawrxd";
    s.history.push_back({"user", "hi"});
    s.history.push_back({"assistant", "hello"});
    if (!rawr::SaveSession(s)) { puts("RAWRXD_AGENT_SESSION_001=FAIL"); return 1; }
    rawr::SessionState t{};
    if (!rawr::LoadSession(s.id, t) || t.history.size() < 2) {
        puts("RAWRXD_AGENT_SESSION_001=FAIL");
        return 1;
    }
    puts("RAWRXD_AGENT_SESSION_001=PASS");
    return 0;
}
