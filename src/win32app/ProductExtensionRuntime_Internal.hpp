// Internal accessors for ProductExtensionRuntime TUs (≤99 lines each).
#pragma once
#include "ProductExtensionRuntime.hpp"
#include <filesystem>
#include <mutex>
#include <unordered_map>
#include <string>

namespace ProductExtensionRuntime {
std::mutex& Mu();
std::unordered_map<std::string, ExtRecord>& Exts();
HostState& Host();
const std::string& ProjectRoot();
const std::string& ExeDir();
const std::string& TogglePath();
std::string Escape(const std::string& s);
bool ReadPackageJson(const std::filesystem::path& dir, ExtRecord& out);
bool PersistTogglesUnlocked();
bool LoadTogglesUnlocked();
int ScanUnlocked();
bool SpawnHostUnlocked(ExtRecord& rec);
void CloseHostUnlocked();
} // namespace ProductExtensionRuntime
