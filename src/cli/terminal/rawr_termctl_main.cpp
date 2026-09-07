// rawr_termctl_main.cpp
#include "rawr_terminal_commands.hpp"
#include <string>
#include <vector>

static std::string joinFrom(int i, int argc, char** argv) {
    std::string s;
    for (; i < argc; ++i) {
        if (!s.empty()) s.push_back(' ');
        s += argv[i];
    }
    return s;
}

static std::string hostPathNear(const char* argv0) {
    std::string p = argv0 ? argv0 : "";
    auto slash = p.find_last_of("\\/");
    std::string dir = slash == std::string::npos ? "." : p.substr(0, slash);
    return dir + "\\rawr_terminal_host.exe";
}

int main(int argc, char** argv) {
    if (argc < 2) {
        fprintf(stderr,
                "rawr_termctl start|tail|status|send|stop|list|killall\n");
        return 1;
    }
    std::string host = hostPathNear(argv[0]);
    std::string sub = argv[1];
    std::string name, rest;
    if (sub == "list" || sub == "killall")
        return rawr::term::CmdTermDispatch(host, sub, "", "");
    if (argc < 3) return 1;
    name = argv[2];
    // start/send: optional -- then command
    int i = 3;
    if (i < argc && std::string(argv[i]) == "--") ++i;
    rest = joinFrom(i, argc, argv);
    return rawr::term::CmdTermDispatch(host, sub, name, rest);
}
