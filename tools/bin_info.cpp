// =============================================================================
// bin_info.cpp — R1 CLI: identify a binary's format/arch/entry/sections.
// =============================================================================
#include <cstdio>
#include <string>

#include "reverse_engineering/binary_loaders.h"

int main(int argc, char** argv) {
    if (argc < 2) {
        std::fprintf(stderr, "usage: bin_info <binary>\n");
        return 2;
    }
    rawrxd::re::BinaryLoader loader;
    rawrxd::re::BinaryInfo info;
    if (!loader.Load(argv[1], info)) {
        std::fprintf(stderr, "bin_info: unknown or malformed format\n");
        return 1;
    }
    std::fputs(rawrxd::re::BinaryLoader::ToJson(info).c_str(), stdout);
    std::fprintf(stderr, "bin_info: %s %s entry=0x%llx sections=%zu\n",
                 rawrxd::re::BinaryLoader::FormatName(info.format),
                 info.arch.c_str(), (unsigned long long)info.entry,
                 info.sections.size());
    return 0;
}