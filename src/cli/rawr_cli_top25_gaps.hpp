#pragma once
// C44/C45/C46/C47 CLI product probes — SOURCE_WIRED, PROMOTE=0.
#include <string>
#include <vector>

int rawrCliMarketplaceCommand(const std::vector<std::string>& args, bool json);
int rawrCliComputerUseCommand(const std::vector<std::string>& args, bool json);
int rawrCliCollabCommand(const std::vector<std::string>& args, bool json);
int rawrCliInstallerCommand(const std::vector<std::string>& args, bool json);
