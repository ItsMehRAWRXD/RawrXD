// standalone_unified.cpp — Diagnostic binary: rawrxd-unified.exe
// Build: cmake --build . --target rawrxd-unified
#include "cli/cli_entrypoints.hpp"
int main(int argc, char** argv) {
    return RawrXD::CLI::RunUnifiedCLI(argc, argv);
}
