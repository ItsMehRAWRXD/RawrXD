#pragma once

#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

namespace rawrxd::models {

struct ModelRecord {
    std::string name;
    std::filesystem::path path;
    uintmax_t bytes = 0;
};

struct ResolveResult {
    bool found = false;
    std::string requested;
    std::filesystem::path path;
    std::string error;
    std::vector<std::filesystem::path> searchedRoots;
};

// Resolves a GGUF path or a local/Ollama-style model name without invoking a
// shell or relying on a process-local hard-coded alias table.
ResolveResult resolve(const std::string& requested);

// Enumerates local GGUF files for the `rawr models` discovery command.
std::vector<ModelRecord> enumerate();

// Chooses a useful workspace for the IDE route. RAWRXD_WORKSPACE wins; then
// the current repository; then the known local checkout if it exists.
std::filesystem::path defaultWorkspace();

} // namespace rawrxd::models
