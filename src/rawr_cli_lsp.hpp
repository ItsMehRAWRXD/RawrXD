#pragma once
#include <string>

namespace rawr_lsp {
// Real clangd JSON-RPC probe. Returns 0 when initialize+hover succeed.
int ProbeClangd(const std::string& workspaceRoot, std::string& outLine);
}
