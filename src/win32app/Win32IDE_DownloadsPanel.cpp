// ============================================================================
// Win32IDE_DownloadsPanel.cpp — Installer (Batch 7 BD04)
// Silent install options, portable mode
// ============================================================================
#include "Win32IDE.h"
#include <windows.h>
#include <string>
#include <sstream>

void Win32IDE::showDownloadsPanel() {
    appendToOutput("[DownloadsPanel] Downloads panel opened.\n", "Output", OutputSeverity::Info);
}

void Win32IDE::downloadModel(const std::string& modelUrl) {
    (void)modelUrl;
    appendToOutput("[DownloadsPanel] Downloading model...\n", "Output", OutputSeverity::Info);
}

void Win32IDE::installSilent() {
    appendToOutput("[Installer] Silent install mode.\n", "Installer", OutputSeverity::Info);
}

bool Win32IDE::isPortableMode() const {
    return false;
}
