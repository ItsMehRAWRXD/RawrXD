// MasmLspSession — real in-process LSP protocol session for .asm / MASM.
// Used by ProductExtensionRuntime_MasmProbe and Win32IDE Assembly LSP path.
// Fail-closed: lsp_asm=1 only when initialize + didOpen + hover/completion succeed.
#pragma once
#include <string>

namespace RawrXD {
namespace LSPServer {

struct MasmLspProbeResult {
    bool ok = false;
    bool initOk = false;
    bool didOpenOk = false;
    bool featureOk = false;  // hover and/or completion hit
    int symbolsIndexed = 0;
    std::string detail;
};

// Runs initialize → initialized → didOpen → hover + completion against asmText.
// Does not invent PASS: featureOk requires symbol evidence (e.g. PROC name).
MasmLspProbeResult RunMasmLspProtocolSession(const std::string& rootPath,
                                             const std::string& asmPath,
                                             const std::string& asmText);

}  // namespace LSPServer
}  // namespace RawrXD
