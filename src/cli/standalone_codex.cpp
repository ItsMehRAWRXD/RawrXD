// standalone_codex.cpp — Diagnostic binary: rawrxd-codex.exe
// Build: cmake --build . --target rawrxd-codex
#include "cli/cli_entrypoints.hpp"
int main(int argc, char** argv) {
    return RawrXD::CLI::RunCodexCLI(argc, argv);
}
