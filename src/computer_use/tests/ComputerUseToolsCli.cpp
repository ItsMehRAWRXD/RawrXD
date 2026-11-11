// Thin CU tools CLI: same Bridge RegisterTools path AgenticLoop/rawr uses.
// argv: tools list | tools run <name> [key=value ...]
#include "ComputerUseBridge.h"
#include "agentic/tool_core.hpp"
#include <cstdio>
#include <cstring>
#include <string>

int main(int argc, char** argv) {
    using rawrxd::tools::Registry;
    using rawrxd::tools::Request;
    using rawrxd::tools::Approval;
    auto& cu = rawrxd::computer_use::ComputerUseBridge::Instance();
    cu.EnsureInitialized();
    cu.AllowOwnAndConfiguredParents();
    cu.ResetCancel();
    Registry reg;
    cu.RegisterTools(reg);

    if (argc < 2) {
        std::fprintf(stderr, "Usage: rawrxd_computer_use_tools_cli tools list|run ...\n");
        return 2;
    }
    if (std::strcmp(argv[1], "tools") != 0 || argc < 3) {
        std::fprintf(stderr, "Usage: tools list|run <name> [k=v ...]\n");
        return 2;
    }
    if (std::strcmp(argv[2], "list") == 0) {
        std::printf("=== Tools ===\n");
        for (const auto& n : reg.names()) std::printf("%s\n", n.c_str());
        return 0;
    }
    if (std::strcmp(argv[2], "run") == 0) {
        if (argc < 4) {
            std::fprintf(stderr, "Usage: tools run <name> [k=v ...]\n");
            return 2;
        }
        Request req;
        req.name = argv[3];
        for (int i = 4; i < argc; ++i) {
            const char* kv = argv[i];
            const char* eq = std::strchr(kv, '=');
            if (!eq) continue;
            req.args.emplace(std::string(kv, eq), std::string(eq + 1));
        }
        Approval always = [](const rawrxd::tools::Tool&, const Request&) {
            return true;
        };
        const auto result = reg.call(req, always);
        if (!result.ok) {
            std::fprintf(stderr, "error=%s\n", result.error.c_str());
            return 1;
        }
        std::printf("%s\n", result.output.c_str());
        return 0;
    }
    std::fprintf(stderr, "Unknown argv\n");
    return 2;
}
