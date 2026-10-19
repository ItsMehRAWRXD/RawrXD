// rawr_argument_parser.hpp
#pragma once
#include "rawr_safety_policy.hpp"
#include <cstdlib>
#include <cstring>
#include <cstdio>
#include <string>
#include <vector>
#ifdef _WIN32
#include <io.h>
#endif

namespace rawr {

struct CliArgs {
    std::string cmd;
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
    uint32_t maxTokens = 0;
    bool help = false;
    bool verbose = false;
    bool refresh = false;
    bool vulkan = false;
};

inline void ReadStdinPrompt(std::string& prompt) {
#ifdef _WIN32
    if (_isatty(_fileno(stdin))) return;
#endif
    if (!prompt.empty()) return;
    char buf[4096];
    while (std::fgets(buf, sizeof(buf), stdin)) prompt += buf;
    while (!prompt.empty() &&
           (prompt.back() == '\n' || prompt.back() == '\r'))
        prompt.pop_back();
}

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
        // Reject unknown flags (anything starting with '-' that isn't a known option)
        if (s[0] == '-' && s[1] != '\0') {
            bool known = false;
            if (!std::strcmp(s, "--help") || !std::strcmp(s, "-h")) known = true;
            else if (!std::strcmp(s, "--verbose") || !std::strcmp(s, "--trace") ||
                     !std::strcmp(s, "-v")) known = true;
            else if (!std::strcmp(s, "--refresh")) known = true;
            else if (!std::strcmp(s, "--no-vulkan")) known = true;
            else if (!std::strcmp(s, "--vulkan")) known = true;
            else if (!std::strcmp(s, "-p") || !std::strcmp(s, "--prompt")) known = true;
            else if (!std::strcmp(s, "--workspace")) known = true;
            else if (!std::strcmp(s, "--term")) known = true;
            else if (!std::strncmp(s, "--profile=", 10)) known = true;
            else if (!std::strncmp(s, "--auto=", 7)) known = true;
            else if (!std::strcmp(s, "--max-tokens") || !std::strcmp(s, "-n") ||
                     !std::strcmp(s, "--tokens")) known = true;
            else if (!std::strncmp(s, "--max-tokens=", 13) ||
                     !std::strncmp(s, "--tokens=", 9)) known = true;
            if (!known) {
                std::fprintf(stderr,
                    "rawr: unknown argument '%s'\n"
                    "Use 'rawr --help' for usage.\n", s);
                a.help = true;
                return a;
            }
        }
        if (!std::strcmp(s, "--help") || !std::strcmp(s, "-h")) a.help = true;
        else if (!std::strcmp(s, "--verbose") || !std::strcmp(s, "--trace") ||
                 !std::strcmp(s, "-v"))
            a.verbose = true;
        else if (!std::strcmp(s, "--refresh")) a.refresh = true;
        else if (!std::strcmp(s, "--no-vulkan")) a.vulkan = false;
        else if (!std::strcmp(s, "--vulkan")) a.vulkan = true;
        else if ((!std::strcmp(s, "-p") || !std::strcmp(s, "--prompt")) &&
                 i + 1 < argc)
            a.prompt = argv[++i];
        else if (!std::strcmp(s, "--workspace") && i + 1 < argc)
            a.workspace = argv[++i];
        else if (!std::strcmp(s, "--term") && i + 1 < argc)
            a.bindTerm = argv[++i];
        else if (!std::strncmp(s, "--profile=", 10)) a.styleProfile = s + 10;
        else if (!std::strncmp(s, "--auto=", 7))
            a.autoLevel = ParseAutonomy(s + 7);
        else if ((!std::strcmp(s, "--max-tokens") || !std::strcmp(s, "-n") ||
                  !std::strcmp(s, "--tokens")) && i + 1 < argc)
            a.maxTokens = (uint32_t)std::atoi(argv[++i]);
        else if (!std::strncmp(s, "--max-tokens=", 13) ||
                 !std::strncmp(s, "--tokens=", 9))
            a.maxTokens = (uint32_t)std::atoi(s + 13);
        else if (a.cmd == "resume" && a.sessionId.empty()) a.sessionId = s;
        else if (a.cmd == "show" && a.model.empty()) a.model = s;
        else if (a.model.empty() && a.cmd != "steer" && a.cmd != "list" &&
                 a.cmd != "paths")
            a.model = s;
        else if (a.cmd == "steer" && a.model.empty()) a.model = s;
        else {
            if (!a.prompt.empty()) a.prompt.push_back(' ');
            a.prompt += s;
        }
    }
    if (a.cmd == "run") ReadStdinPrompt(a.prompt);
    if (a.workspace.empty()) a.workspace = "G:\\~dev\\rawrxd";
    return a;
}

} // namespace rawr
