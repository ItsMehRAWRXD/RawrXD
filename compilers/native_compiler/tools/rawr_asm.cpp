// rawr_asm — the first-party assembler as a command line tool.
//
//   rawr_asm <source.asm> <out.obj>
//
// The assembler itself is the certified implementation in src/asm. This is
// only the driver around it, so that the compiler pipeline can compose
// stages the way the certification suites already do.
//
// The recovered C front end expected an external assembler binary at a
// hardcoded path. This is the one it needed, built from the first-party
// source.

#include "asm/X64Assembler.h"
#include "rawrstd/string.h"
#include "rawrstd/sys.h"

#include <cstdio>

int main(int argc, char** argv) {
    if (argc < 3) {
        std::fprintf(stderr, "usage: rawr_asm <source.asm> <out.obj>\n");
        return 2;
    }

    rawrstd::String error;
    if (!rawr::assembleX64File(rawrstd::String(argv[1]), rawrstd::String(argv[2]), error)) {
        std::fprintf(stderr, "rawr_asm: %s\n", error.data());
        return 1;
    }
    std::printf("rawr_asm: wrote %s\n", argv[2]);
    return 0;
}
