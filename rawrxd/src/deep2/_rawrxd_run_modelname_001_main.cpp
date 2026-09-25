// Temporary wrapper to build rawrxd_run_modelname_001.exe standalone
#include "rawrxd_run_modelname_001.h"
#include <cstdio>
#include <string>

int main(int argc, char** argv) {
    if (argc < 3) {
        std::fprintf(stderr,
            "Usage: rawrxd_run_modelname_001 <model_or_path> <prompt>\n"
            "  <model_or_path>  GGUF path or model alias\n"
            "  <prompt>          Text prompt\n");
        return 1;
    }
    std::string prompt;
    for (int i = 2; i < argc; ++i) {
        if (i > 2) prompt += ' ';
        prompt += argv[i];
    }
    return rawrxd_run_modelname_001(argv[1], prompt.c_str(), 512, false);
}
