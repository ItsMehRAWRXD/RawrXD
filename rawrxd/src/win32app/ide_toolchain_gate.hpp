// ============================================================================
// ide_toolchain_gate.hpp — IDE-native toolchain gate (RAWRXD_WIN32IDE_TOOLCHAIN_001)
// ============================================================================
#pragma once

#include <string>

namespace RawrXD::IDE {

struct ToolchainResult {
    bool jitOk      = false;
    bool coffOk     = false;
    bool peOk       = false;
    bool helloRunOk = false;
    std::string exePath;
    std::string diagnostics;
};

/// Run JIT, COFF, PE64, and hello.exe verification entirely inside the IDE.
/// No external tools. No stubs.
ToolchainResult runNativeToolchainGate();

} // namespace RawrXD::IDE
