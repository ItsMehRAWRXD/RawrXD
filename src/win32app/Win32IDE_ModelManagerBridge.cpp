// ============================================================================
// Win32IDE_ModelManagerBridge.cpp — Bridge from Win32IDE to ModelManager dialog
// ============================================================================

#include "Win32IDE.h"
#include "Win32IDE_ModelManager.h"
#include "model_puller/model_puller.h"
#include "../../include/model_puller/download_manager.h"
#include <cstdio>

// Status bar part index for download progress (part 8 of 12)
static constexpr int kStatusBarDownloadPart = 8;

void Win32IDE::showModelManager() {
    LOG_INFO("Opening Model Manager dialog");

    ModelManagerDialog dlg(m_hwndMain, m_hInstance);
    dlg.Show();

    std::string selectedPath = dlg.GetSelectedModelPath();
    if (!selectedPath.empty()) {
        LOG_INFO("Model Manager selected: " + selectedPath);
        // Trigger model reload if active model changed
        scanForModels();
    }
}

// ============================================================================
// Status Bar Download Progress Integration
// ============================================================================
// Call this from model pull operations to show progress on status bar part 8.
// Thread-safe: uses PostMessage/SendMessage which are thread-safe to other threads.
void Win32IDE::updateDownloadProgress(const RawrXD::DownloadProgress& progress) {
    if (!m_hwndStatusBar) return;

    char buf[128];
    if (progress.totalBytes > 0 && progress.progressPercent > 0.0) {
        double mbDone = static_cast<double>(progress.bytesDownloaded) / (1024.0 * 1024.0);
        double mbTotal = static_cast<double>(progress.totalBytes) / (1024.0 * 1024.0);
        double speedMBs = progress.speedBytesPerSec / (1024.0 * 1024.0);
        snprintf(buf, sizeof(buf), "DL: %.0f%% (%.0f/%.0f MB, %.1f MB/s)",
                 progress.progressPercent, mbDone, mbTotal, speedMBs);
    } else if (progress.bytesDownloaded > 0) {
        double mbDone = static_cast<double>(progress.bytesDownloaded) / (1024.0 * 1024.0);
        snprintf(buf, sizeof(buf), "DL: %.0f MB", mbDone);
    } else {
        snprintf(buf, sizeof(buf), "Connecting...");
    }

    SendMessageA(m_hwndStatusBar, SB_SETTEXTA, kStatusBarDownloadPart, reinterpret_cast<LPARAM>(buf));
}

void Win32IDE::clearDownloadProgress() {
    if (!m_hwndStatusBar) return;
    SendMessageA(m_hwndStatusBar, SB_SETTEXTA, kStatusBarDownloadPart, reinterpret_cast<LPARAM>(""));
}
