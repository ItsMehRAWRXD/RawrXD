// rawr_c — the C front end as a command line tool.
//
//   rawr_c <source.c> <out.asm>
//
// The front end itself is in src/frontend/c_stage2.cpp. This is only the
// driver around it, so that the pipeline can be composed:
//
//     rawr_c      C source  ->  assembly
//     rawr_asm    assembly  ->  COFF object
//     rawrxd_link object    ->  Windows executable
//
// Every stage in that chain is first-party.

#include "frontend/c_stage2.h"
#include "rawrstd/string.h"

#include <cstdio>

int main(int argc, char** argv) {
    if (argc < 3) {
        std::fprintf(stderr, "usage: rawr_c <source.c> <out.asm>\n");
        return 2;
    }

    rawrstd::String error;
    if (!rawr::c_compile_to_asm(argv[1], argv[2], &error)) {
        std::fprintf(stderr, "rawr_c: %s\n", error.data());
        return 1;
    }
    std::printf("rawr_c: wrote %s\n", argv[2]);
    return 0;
}
