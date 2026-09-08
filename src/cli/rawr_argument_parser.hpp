// rawr_argument_parser.hpp
#pragma once
#include "rawr_safety_policy.hpp"
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

namespace rawr {

struct CliArgs {
    std::string cmd; // run|chat|agent|steer|resume|term
    std::string model;
    std::string prompt;
    std::string workspace;
    std::string sessionId;
    std::string termSub;
    std::string termName;
    std::string termCmd;
    std::string bindTerm;
    std::string styleProfile;
    std::string pipeName;
    unsigned short httpPort = 0;
    AutonomyLevel autoLevel = AutonomyLevel::Off;
    uint32_t maxTokens = 0; // 0 → CmdRun default
    bool help = false;
};

inline CliArgs ParseArgs(int argc, char** argv) {
    CliArgs a{};
    if (argc < 2) {
        a.help = true;
        return a;
    }
    a.cmd = argv[1] ? argv[1] : "";
    if (a.cmd == "term") {
        if (argc >= 3) a.termSub = argv[2] ? argv[2] : "";
        int i = 3;
        if (a.termSub != "list" && a.termSub != "killall" && i < argc) {
            a.termName = argv[i] ? argv[i] : "";
            ++i;
        }
        if (i < argc && argv[i] && !std::strcmp(argv[i], "--")) ++i;
        for (; i < argc; ++i) {
            if (!a.termCmd.empty()) a.termCmd.push_back(' ');
            a.termCmd += argv[i] ? argv[i] : "";
        }
        if (a.termSub == "send" || a.termSub == "tail") a.prompt = a.termCmd;
        if (a.workspace.empty()) a.workspace = "G:\\~dev\\rawrxd";
        return a;
    }
    if (a.cmd == "serve") {
        a.pipeName = "\\\\.\\pipe\\rawrxd_product";
        for (int i = 2; i < argc; ++i) {
            if (argv[i] && !std::strcmp(argv[i], "--pipe") && i + 1 < argc)
                a.pipeName = argv[++i];
            else if (argv[i] && !std::strcmp(argv[i], "--http"))
                a.httpPort = 11435;
            else if (argv[i] && !std::strcmp(argv[i], "--port") && i + 1 < argc)
                a.httpPort = (unsigned short)std::atoi(argv[++i]);
        }
        return a;
    }
    for (int i = 2; i < argc; ++i) {
        const char* s = argv[i];
        if (!s) continue;
        if (!std::strcmp(s, "--help") || !std::strcmp(s, "-h")) {
            a.help = true;
        } else if (!std::strcmp(s, "--workspace") && i + 1 < argc) {
            a.workspace = argv[++i];
        } else if (!std::strcmp(s, "--term") && i + 1 < argc) {
            a.bindTerm = argv[++i];
        } else if (!std::strncmp(s, "--profile=", 10)) {
            a.styleProfile = s + 10;
        } else if (!std::strncmp(s, "--auto=", 7)) {
            a.autoLevel = ParseAutonomy(s + 7);
        } else if ((!std::strcmp(s, "--max-tokens") || !std::strcmp(s, "-n")) &&
                   i + 1 < argc) {
            a.maxTokens = (uint32_t)std::atoi(argv[++i]);
        } else if (!std::strncmp(s, "--max-tokens=", 13)) {
            a.maxTokens = (uint32_t)std::atoi(s + 13);
        } else if (a.cmd == "resume" && a.sessionId.empty()) {
            a.sessionId = s;
        } else if (a.cmd == "steer" && !a.model.empty() &&
                   (std::strcmp(s, "pause") == 0 ||
                    std::strcmp(s, "continue") == 0 ||
                    std::strcmp(s, "stop") == 0 ||
                    std::strncmp(s, "show", 4) == 0 ||
                    std::strncmp(s, "undo", 4) == 0 ||
                    std::strncmp(s, "run", 3) == 0 ||
                    std::strncmp(s, "change", 6) == 0 ||
                    std::strncmp(s, "explain", 7) == 0 ||
                    std::strncmp(s, "approve", 7) == 0 ||
                    std::strncmp(s, "reject", 6) == 0 ||
                    std::strncmp(s, "tail", 4) == 0)) {
            if (!a.prompt.empty()) a.prompt.push_back(' ');
            a.prompt += s;
        } else if (a.model.empty() && a.cmd != "steer") {
            a.model = s;
        } else if (a.cmd == "steer" && a.model.empty()) {
            a.model = s;
        } else {
            if (!a.prompt.empty()) a.prompt.push_back(' ');
            a.prompt += s;
        }
    }
    if (a.workspace.empty()) a.workspace = "G:\\~dev\\rawrxd";
    return a;
}

} // namespace rawr
