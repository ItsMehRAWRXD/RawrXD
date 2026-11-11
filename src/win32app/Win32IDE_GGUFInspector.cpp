// Win32IDE_GGUFInspector.cpp — GGUF Parser (Batch 5 M06)
// Tensor loading, quantization scheme detection
#include "Win32IDE.h"
#include <windows.h>
#include <string>
#include <fstream>

struct GGUFInfo {
    std::string filename;
    std::string quantization;
    int tensorCount;
    size_t fileSize;
};

static std::vector<GGUFInfo> g_ggufLibrary;

void Win32IDE::scanGGUFModels(const std::string& rootPath) {
    // Stub: scan for GGUF files
    appendToOutput("[GGUFInspector] Scanning for GGUF models.\n", "Output", OutputSeverity::Info);
}

std::vector<GGUFInfo> Win32IDE::listGGUFModels() const {
    return g_ggufLibrary;
}
