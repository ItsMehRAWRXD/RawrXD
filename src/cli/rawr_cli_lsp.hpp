#pragma once
#include <string>
#include <vector>

// C36–C38: CLI product path into embedded RawrXDLSPServer (no stubs).
int rawrCliLspCommand(const std::vector<std::string>& args,
                      const std::string& workspaceRoot, bool jsonOut);
