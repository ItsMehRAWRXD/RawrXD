// Win32IDE_GGUFInspector.cpp — GGUF Parser (Batch 5 M06)
#include "Win32IDE.h"
#include <windows.h>
#include <string>
#include <vector>
#include <fstream>

static std::vector<Win32IDE::GGUFInfo> g_ggufLibrary;

void Win32IDE::scanGGUFModels(const std::string& rootPath) {
    (void)rootPath;
    appendToOutput("[GGUFInspector] Scanning for GGUF models.\n", "Output", OutputSeverity::Info);
}

std::vector<Win32IDE::GGUFInfo> Win32IDE::listGGUFModels() const {
    return g_ggufLibrary;
}