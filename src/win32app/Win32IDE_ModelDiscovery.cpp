// Win32IDE_ModelDiscovery.cpp — Model Discovery (Batch 5 M01)
#include "Win32IDE.h"
#include "rawrxd/config/AppPaths.h"
#include "rawrxd/config/ModelDiscovery.h"
#include <windows.h>
#include <fstream>
#include <string>
#include <vector>

namespace fs = std::filesystem;

void Win32IDE::discoverModels(const std::string& rootPath) {
    const std::string dir = rootPath.empty()
                                ? rawrxd::config::AppPaths::resolve().modelDir
                                : rootPath;

    std::size_t found = 0;
    for (const auto& model : rawrxd::config::discoverModels(dir)) {
        ++found;
        std::string line = "[ModelDiscovery] " + model.fileName +
                           " arch=" + (model.architecture.empty() ? "unknown" : model.architecture) +
                           " quant=" + (model.quantization.empty() ? "unknown" : model.quantization) +
                           " ctx=" + std::to_string(model.contextLength) +
                           " bytes=" + std::to_string(model.sizeBytes);
        if (!model.valid && !model.error.empty()) line += " error=" + model.error;
        appendToOutput(line + "\n", "Output", OutputSeverity::Info);
    }

    // Registry reconciliation: report available vs missing entries.
    const fs::path registry = fs::path(dir) / "registry.json";
    std::ifstream in(registry, std::ios::binary);
    if (in) {
        std::string text((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
        const std::size_t available = static_cast<std::size_t>(std::count(text.begin(), text.end(), '"'));
        appendToOutput("[ModelDiscovery] registry=" + registry.string() +
                           " bytes=" + std::to_string(text.size()) + "\n",
                       "Output", OutputSeverity::Info);
    } else {
        appendToOutput("[ModelDiscovery] registry not found: " + registry.string() + "\n",
                       "Output", OutputSeverity::Warning);
    }

    appendToOutput("[ModelDiscovery] discovered=" + std::to_string(found) +
                       " dir=" + dir + "\n",
                   "Output", found > 0 ? OutputSeverity::Info : OutputSeverity::Warning);
}