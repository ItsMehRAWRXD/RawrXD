// Temporary wrapper to build rawrxd_run_modelname_001.exe standalone
#include "rawrxd_run_modelname_001.h"
#include <cstdio>
#include <string>

int main(int argc, char** argv) {
    bool vulkan = false;
    bool strict = false;
    int argOffset = 0;
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--vulkan" || arg == "-vulkan") {
            vulkan = true;
            argOffset++;
        } else if (arg == "--strict-vulkan" || arg == "-strict-vulkan") {
            strict = true;
            argOffset++;
        }
    }
    int req = 1 + argOffset;
    if (argc < req + 2) {
        std::fprintf(stderr,
            "Usage: rawrxd_run_modelname_001 [--vulkan] <model_or_path> <prompt>\n"
            "  --vulkan          Enable Vulkan GPU acceleration\n"
            "  <model_or_path>   GGUF path or model alias\n"
            "  <prompt>           Text prompt\n");
        return 1;
    }
    std::string model = argv[req];
    std::string prompt;
    for (int i = req + 1; i < argc; ++i) {
        if (i > req + 1) prompt += ' ';
        prompt += argv[i];
    }
    std::fprintf(stderr, "[rawrxd_run_modelname_001] vulkan=%s strict=%s\n", vulkan ? "true" : "false", strict ? "true" : "false");
    return rawrxd_run_modelname_001(model.c_str(), prompt.c_str(), 512, vulkan, strict);
}
