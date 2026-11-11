// Win32IDE_ModelDiscovery.cpp — Model Discovery (Batch 5 M01)
// Discover GGUF/ONNX models on local drives
#include "Win32IDE.h"
#include <windows.h>
#include <string>
#include <vector>
#include <filesystem>

namespace fs = std::filesystem;

void Win32IDE::discoverModels(const std::string& rootPath) {
    try {
        for (const auto& entry : fs::recursive_directory_iterator(rootPath)) {
            if (entry.is_regular_file()) {
                std::string ext = entry.path().extension().string();
                if (ext == ".gguf" || ext == ".onnx") {
                    appendToOutput("[ModelDiscovery] Found: " + entry.path().string() + "\n",
                                   "Output", OutputSeverity::Info);
                }
            }
        }
    } catch (...) {}
}
