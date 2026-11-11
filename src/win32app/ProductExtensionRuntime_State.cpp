// ProductExtensionRuntime_State.cpp — shared state + roots.
#include "ProductExtensionRuntime.hpp"
#include <filesystem>

namespace ProductExtensionRuntime {
namespace {
std::mutex g_mu;
std::unordered_map<std::string, ExtRecord> g_exts;
HostState g_host;
std::string g_projectRoot;
std::string g_exeDir;
std::string g_togglePath;
}

std::mutex& Mu() { return g_mu; }
std::unordered_map<std::string, ExtRecord>& Exts() { return g_exts; }
HostState& Host() { return g_host; }
const std::string& ProjectRoot() { return g_projectRoot; }
const std::string& ExeDir() { return g_exeDir; }
const std::string& TogglePath() { return g_togglePath; }

void SetRoots(const std::string& projectRoot, const std::string& exeDir) {
    std::lock_guard<std::mutex> lock(g_mu);
    g_projectRoot = projectRoot;
    g_exeDir = exeDir;
    std::filesystem::path p = projectRoot.empty() ? exeDir : projectRoot;
    g_togglePath = (p / ".rawrxd" / "extension_toggles.json").string();
}

} // namespace ProductExtensionRuntime
