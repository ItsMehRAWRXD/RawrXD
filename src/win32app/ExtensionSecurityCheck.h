#pragma once

#include <string>

namespace ExtensionSecurity {

bool CheckExtensionSignature(const std::string& extensionPath);
bool ScanForMaliciousPatterns(const std::string& content);
bool PromptUserApproval(const std::string& action);

}
