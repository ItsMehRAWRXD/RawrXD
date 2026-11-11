// Win32IDE_ModelLab.cpp — Model Browser (Batch 5 M01)
#include "Win32IDE.h"
#include <windows.h>
#include <string>
#include <vector>

static std::vector<Win32IDE::ModelInfo> g_modelLibrary;

void Win32IDE::initModelLab() {
    g_modelLibrary.clear();
    appendToOutput("[ModelLab] Model browser initialized.\n", "Output", OutputSeverity::Info);
}

void Win32IDE::addModel(const std::string& name, const std::string& path,
                         const std::string& format, size_t size) {
    Win32IDE::ModelInfo info;
    info.name = name;
    info.path = path;
    info.format = format;
    info.size = size;
    g_modelLibrary.push_back(info);
}

void Win32IDE::removeModel(const std::string& name) {
    for (auto it = g_modelLibrary.begin(); it != g_modelLibrary.end(); ++it) {
        if (it->name == name) {
            g_modelLibrary.erase(it);
            return;
        }
    }
}

std::vector<Win32IDE::ModelInfo> Win32IDE::listModels() const {
    return g_modelLibrary;
}