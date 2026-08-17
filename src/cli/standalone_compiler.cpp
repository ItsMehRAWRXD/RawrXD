// standalone_compiler.cpp — Diagnostic binary: rawrxd-compile.exe
// Build: cmake --build . --target rawrxd-compile
#include "cli/cli_entrypoints.hpp"
int main(int argc, char** argv) {
    return RawrXD::CLI::RunCompilerCLI(argc, argv);
}
