// standalone_infer.cpp — Diagnostic binary: rawrxd-infer.exe
// Build: cmake --build . --target rawrxd-infer
#include "cli/cli_entrypoints.hpp"
int main(int argc, char** argv) {
    return RawrXD::CLI::RunInferenceCLI(argc, argv);
}
