#include "../src/cli/rawr_resume.hpp"
#include <cstdio>
int main() {
    rawr::SessionState s{};
    s.id = "cert_resume_001";
    s.modelAlias = "tinyllama";
    s.workspace = "G:\\~dev\\rawrxd";
    s.history.push_back({"user", "resume-me"});
    if (!rawr::SaveSession(s)) { puts("RAWRXD_AGENT_RESUME_001=FAIL"); return 1; }
    rawr::SessionState t{};
    if (!rawr::ResumeSession(s.id, t) || t.history.empty()) {
        puts("RAWRXD_AGENT_RESUME_001=FAIL");
        return 1;
    }
    puts("RAWRXD_AGENT_RESUME_001=PASS");
    return 0;
}
