// ExtensionHostWorker_Parse.cpp — cmdline flag parse for ExtensionHost worker.
#include "ExtensionHostWorker_Activate.h"
#include <cstdio>
#include <cstring>
#include <string>

static void takeFlag(std::string& rest, const char* flag, char* dest, size_t n) {
    std::string f(flag);
    size_t p = rest.find(f);
    if (p == std::string::npos) return;
    rest = rest.substr(p + f.size());
    while (!rest.empty() && (rest[0] == ' ' || rest[0] == '=')) rest.erase(rest.begin());
    if (!rest.empty() && rest[0] == '"') {
        size_t e = rest.find('"', 1);
        if (e != std::string::npos) {
            std::snprintf(dest, n, "%s", rest.substr(1, e - 1).c_str());
            return;
        }
    }
    size_t e = rest.find(" --");
    std::string v = (e == std::string::npos) ? rest : rest.substr(0, e);
    while (!v.empty() && v.back() == ' ') v.pop_back();
    std::snprintf(dest, n, "%s", v.c_str());
}

void ExtHost_ParseArgs(const char* cmdLine, ExtHostActivateResult* out) {
    if (!out) return;
    std::memset(out, 0, sizeof(*out));
    out->processAlive = 1;
    if (!cmdLine || !*cmdLine) return;
    std::string rest(cmdLine);
    takeFlag(rest, "--extension-id", out->extensionId, sizeof(out->extensionId));
    takeFlag(rest, "--extension-path", out->extensionPath, sizeof(out->extensionPath));
}
