// ============================================================================
// Win32IDE_ExtensionManager.cpp — Extension Manager wired to marketplace stack
// ============================================================================
// Routes all extension commands to:
//   • ExtensionAutoInstaller  — marketplace query + VSIX download + install
//   • VSCodeMarketplace       — low-level query/download
//   • RawrXD::VSIXInstaller   — secure VSIX extraction and verification
//   • ExtensionLoader         — local extension discovery and reload
//
// Architecture: C++20 | Win32 | No exceptions | No Qt
// Rule: NO SOURCE FILE IS TO BE SIMPLIFIED
// ============================================================================
#include "Win32IDE.h"
#include "IDELogger.h"
#include "VSCodeMarketplaceAPI.hpp"
#include "VSIXInstaller.hpp"
#include "../marketplace/extension_auto_installer.hpp"
#include "../modules/ExtensionLoader.hpp"
#include <commctrl.h>
#include <commdlg.h>
#include <sstream>
#include <thread>

using namespace RawrXD::Extensions;

// ── Internal helpers ───────────────────────────────────────────────────────

// Push a status line to the extension details control (best-effort; null-safe).
static void SetExtStatus(HWND hwndDetails, const std::string& msg) {
    if (hwndDetails)
        SetWindowTextA(hwndDetails, msg.c_str());
    RAWRXD_LOG_INFO("ExtensionManager") << msg;
}

// ── listExtensions ─────────────────────────────────────────────────────────
void Win32IDE::listExtensions()
{
    // Reload installed extensions from disk then repopulate the list view.
    ExtensionLoader& loader = ExtensionLoader::GetInstance();
    loader.ScanExtensionsDirectory();
    loadInstalledExtensions();
    SetExtStatus(m_hwndExtensionDetails, "Extensions refreshed.");
    RAWRXD_LOG_INFO("ExtensionManager") << "listExtensions: scan complete";
}

// ── searchExtensions ───────────────────────────────────────────────────────
void Win32IDE::searchExtensions(const std::string& query)
{
    if (query.empty()) {
        listExtensions();
        return;
    }

    // Fill the search box and repopulate (UI-only filter; live marketplace
    // search is initiated from the MarketplacePanel separately).
    if (m_hwndExtensionSearch)
        SetWindowTextA(m_hwndExtensionSearch, query.c_str());

    RAWRXD_LOG_INFO("ExtensionManager") << "searchExtensions: query=" << query;

    // Async marketplace query — fire and forget; results come back via panel.
    std::thread([query]() {
        std::vector<VSCodeMarketplace::MarketplaceEntry> results;
        if (VSCodeMarketplace::Query(query, 25, 1, results)) {
            std::ostringstream oss;
            oss << "Marketplace results for \"" << query << "\":\n";
            for (const auto& e : results) {
                oss << "  " << e.id << "  (" << e.displayName << ")  v" << e.version << "\n";
            }
            RAWRXD_LOG_INFO("ExtensionManager") << oss.str();
        } else {
            RAWRXD_LOG_WARNING("ExtensionManager") << "searchExtensions: marketplace query failed for: " << query;
        }
    }).detach();
}

// ── installExtension ───────────────────────────────────────────────────────
void Win32IDE::installExtension(const std::string& id)
{
    if (id.empty()) {
        SetExtStatus(m_hwndExtensionDetails, "installExtension: empty id rejected.");
        return;
    }

    SetExtStatus(m_hwndExtensionDetails, "Installing " + id + "...");
    RAWRXD_LOG_INFO("ExtensionManager") << "installExtension: " << id;

    // Run on background thread — WinHTTP download must not block the UI pump.
    std::thread([this, id]() {
        auto progressCb = [this, id](const InstallProgress& p) {
            std::string status;
            switch (p.stage) {
                case InstallProgress::Stage::Querying:    status = "Querying marketplace for " + id + "..."; break;
                case InstallProgress::Stage::Downloading: status = "Downloading " + id + "..."; break;
                case InstallProgress::Stage::Installing:  status = "Extracting and installing " + id + "..."; break;
                case InstallProgress::Stage::Verifying:   status = "Verifying " + id + "..."; break;
                case InstallProgress::Stage::Complete:    status = id + " installed successfully."; break;
                case InstallProgress::Stage::Failed:
                    status = std::string("Install failed: ") + (p.detail ? p.detail : "unknown error");
                    break;
            }
            // Marshal status text update back to UI thread.
            if (m_hwnd) {
                std::string* pStatus = new std::string(status);
                PostMessageA(m_hwnd, WM_APP + 0x210, 0, reinterpret_cast<LPARAM>(pStatus));
            }
        };

        AutoInstallResult result =
            ExtensionAutoInstaller::instance().installExtension(id, progressCb);

        if (result.success) {
            RAWRXD_LOG_INFO("ExtensionManager") << "installExtension: succeeded: " << id;
            // Reload extension loader so the new extension is live.
            ExtensionLoader::GetInstance().ScanExtensionsDirectory();
        } else {
            RAWRXD_LOG_ERROR("ExtensionManager")
                << "installExtension: failed: " << id
                << " code=" << result.errorCode << " " << result.detail;
        }
    }).detach();
}

// ── uninstallExtension ─────────────────────────────────────────────────────
void Win32IDE::uninstallExtension(const std::string& id)
{
    if (id.empty()) {
        SetExtStatus(m_hwndExtensionDetails, "uninstallExtension: empty id rejected.");
        return;
    }

    RAWRXD_LOG_INFO("ExtensionManager") << "uninstallExtension: " << id;

    if (RawrXD::VSIXInstaller::Uninstall(id)) {
        SetExtStatus(m_hwndExtensionDetails, id + " uninstalled.");
        ExtensionLoader::GetInstance().ScanExtensionsDirectory();
    } else {
        const std::string msg = "Uninstall failed for: " + id;
        SetExtStatus(m_hwndExtensionDetails, msg);
        RAWRXD_LOG_WARNING("ExtensionManager") << msg;
    }
}

// ── enableExtension ────────────────────────────────────────────────────────
void Win32IDE::enableExtension(const std::string& id)
{
    if (id.empty()) return;
    RAWRXD_LOG_INFO("ExtensionManager") << "enableExtension: " << id;
    if (ExtensionLoader::GetInstance().EnableExtension(id)) {
        SetExtStatus(m_hwndExtensionDetails, id + " enabled.");
    } else {
        SetExtStatus(m_hwndExtensionDetails, "Enable failed for: " + id);
    }
}

// ── disableExtension ───────────────────────────────────────────────────────
void Win32IDE::disableExtension(const std::string& id)
{
    if (id.empty()) return;
    RAWRXD_LOG_INFO("ExtensionManager") << "disableExtension: " << id;
    if (ExtensionLoader::GetInstance().DisableExtension(id)) {
        SetExtStatus(m_hwndExtensionDetails, id + " disabled.");
    } else {
        SetExtStatus(m_hwndExtensionDetails, "Disable failed for: " + id);
    }
}

// ── showExtensionDetails ───────────────────────────────────────────────────
void Win32IDE::showExtensionDetails(const std::string& id)
{
    if (id.empty()) {
        SetExtStatus(m_hwndExtensionDetails, "No extension selected.");
        return;
    }

    // Check local install state first (instant); then fall back to marketplace.
    bool installed = ExtensionAutoInstaller::instance().isInstalled(id);

    std::ostringstream oss;
    oss << "Extension: " << id << "\n"
        << "Status: " << (installed ? "Installed" : "Not installed") << "\n";

    // Fetch live metadata from marketplace.
    VSCodeMarketplace::MarketplaceEntry entry;
    if (VSCodeMarketplace::GetById(id, entry)) {
        oss << "Display Name: " << entry.displayName << "\n"
            << "Publisher:    " << entry.publisher << "\n"
            << "Version:      " << entry.version << "\n"
            << "Installs:     " << entry.installCount << "\n"
            << "Rating:       " << entry.averageRating << " (" << entry.ratingCount << " ratings)\n"
            << "Description:  " << entry.shortDescription << "\n"
            << "Marketplace:  " << VSCodeMarketplace::ItemUrl(entry.publisher, entry.extensionName) << "\n";
    } else {
        oss << "(Marketplace metadata unavailable — offline or unknown extension)\n";
    }

    SetExtStatus(m_hwndExtensionDetails, oss.str());
}

// ── installFromVSIXFile ────────────────────────────────────────────────────
void Win32IDE::installFromVSIXFile()
{
    // Open file picker restricted to .vsix files.
    char filePath[MAX_PATH] = {};
    OPENFILENAMEA ofn = {};
    ofn.lStructSize  = sizeof(ofn);
    ofn.hwndOwner    = m_hwnd;
    ofn.lpstrFilter  = "VSIX Extension\0*.vsix\0All Files\0*.*\0";
    ofn.lpstrFile    = filePath;
    ofn.nMaxFile     = MAX_PATH;
    ofn.lpstrTitle   = "Select VSIX Extension";
    ofn.Flags        = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;

    if (!GetOpenFileNameA(&ofn)) return;  // user cancelled

    SetExtStatus(m_hwndExtensionDetails, std::string("Installing: ") + filePath);
    RAWRXD_LOG_INFO("ExtensionManager") << "installFromVSIXFile: " << filePath;

    const std::string path(filePath);
    std::thread([this, path]() {
        if (RawrXD::VSIXInstaller::Install(path)) {
            const std::string msg = "Installed from: " + path;
            RAWRXD_LOG_INFO("ExtensionManager") << msg;
            if (m_hwnd) {
                std::string* p = new std::string(msg);
                PostMessageA(m_hwnd, WM_APP + 0x210, 0, reinterpret_cast<LPARAM>(p));
            }
            ExtensionLoader::GetInstance().ScanExtensionsDirectory();
        } else {
            const std::string msg = "Install failed for: " + path;
            RAWRXD_LOG_ERROR("ExtensionManager") << msg;
            if (m_hwnd) {
                std::string* p = new std::string(msg);
                PostMessageA(m_hwnd, WM_APP + 0x210, 0, reinterpret_cast<LPARAM>(p));
            }
        }
    }).detach();
}
