// Win32IDE_Settings.cpp — Project Settings (.vscode-style) (Batch 4 P09)
// IDESettings is defined in Win32IDE.h; this TU only provides the static
// storage for Win32IDE::m_settings and the load/save entry points.
#include "Win32IDE.h"
#include <fstream>
#include <sstream>
#include <filesystem>

#include "core/json_util.hpp"

// Static member definition (declared in Win32IDE.h)
IDESettings Win32IDE::m_settings;

namespace {

// Canonical settings path: %APPDATA%\RawrXD\settings.json
std::filesystem::path settingsPath() {
    const char* appData = std::getenv("APPDATA");
    std::filesystem::path root =
        appData ? std::filesystem::path(appData) : std::filesystem::current_path();
    root /= "RawrXD";
    std::error_code ec;
    std::filesystem::create_directories(root, ec);
    return root / "settings.json";
}

} // namespace

void Win32IDE::loadSettings() {
    const std::filesystem::path path = settingsPath();

    std::ifstream in(path, std::ios::binary);
    if (!in.is_open()) {
        appendToOutput("[Settings] No settings file; using defaults.\n",
                       "Output", OutputSeverity::Info);
        return;
    }

    std::ostringstream buf;
    buf << in.rdbuf();
    const std::string text = buf.str();
    if (text.empty()) {
        return;
    }

    nlohmann::json j = nlohmann::json::parse(text, nullptr, false);
    if (j.is_discarded() || !j.is_object()) {
        appendToOutput("[Settings] Settings file unreadable; keeping defaults.\n",
                       "Output", OutputSeverity::Warning);
        return;
    }

    // Editor
    m_settings.fontSize            = j.value("fontSize", m_settings.fontSize);
    m_settings.fontName            = j.value("fontName", m_settings.fontName);
    m_settings.wordWrapEnabled     = j.value("wordWrap", m_settings.wordWrapEnabled);
    m_settings.lineNumbersVisible  = j.value("lineNumbers", m_settings.lineNumbersVisible);
    m_settings.autoSaveEnabled     = j.value("autoSave", m_settings.autoSaveEnabled);
    m_settings.autoSaveIntervalSec = j.value("autoSaveIntervalSec", m_settings.autoSaveIntervalSec);
    m_settings.workingDirectory    = j.value("workingDirectory", m_settings.workingDirectory);

    // AI
    m_settings.aiTemperature  = j.value("aiTemperature", m_settings.aiTemperature);
    m_settings.aiTopP         = j.value("aiTopP", m_settings.aiTopP);
    m_settings.aiTopK         = j.value("aiTopK", m_settings.aiTopK);
    m_settings.aiMaxTokens    = j.value("aiMaxTokens", m_settings.aiMaxTokens);
    m_settings.aiContextWindow= j.value("aiContextWindow", m_settings.aiContextWindow);

    // Appearance
    if (j.contains("appearance") && j["appearance"].is_object()) {
        const auto& a = j["appearance"];
        m_appearance.themeName         = a.value("theme", m_appearance.themeName);
        m_appearance.uiScale           = a.value("uiScale", m_appearance.uiScale);
        m_appearance.fontFamily        = a.value("fontFamily", m_appearance.fontFamily);
        m_appearance.editorFontSizePt  = a.value("editorFontSizePt", m_appearance.editorFontSizePt);
        m_appearance.ligatures         = a.value("ligatures", m_appearance.ligatures);
        m_appearance.tabSize           = a.value("tabSize", m_appearance.tabSize);
        m_appearance.insertSpaces      = a.value("insertSpaces", m_appearance.insertSpaces);
    }

    appendToOutput("[Settings] Loaded from " + path.string() + "\n",
                   "Output", OutputSeverity::Info);
}

void Win32IDE::saveSettings() {
    const std::filesystem::path path = settingsPath();

    nlohmann::json j;
    j["fontSize"]            = m_settings.fontSize;
    j["fontName"]            = m_settings.fontName;
    j["wordWrap"]            = m_settings.wordWrapEnabled;
    j["lineNumbers"]         = m_settings.lineNumbersVisible;
    j["autoSave"]            = m_settings.autoSaveEnabled;
    j["autoSaveIntervalSec"] = m_settings.autoSaveIntervalSec;
    j["workingDirectory"]    = m_settings.workingDirectory;
    j["aiTemperature"]       = m_settings.aiTemperature;
    j["aiTopP"]              = m_settings.aiTopP;
    j["aiTopK"]              = m_settings.aiTopK;
    j["aiMaxTokens"]         = m_settings.aiMaxTokens;
    j["aiContextWindow"]     = m_settings.aiContextWindow;

    j["appearance"] = {
        {"theme",            m_appearance.themeName},
        {"uiScale",          m_appearance.uiScale},
        {"fontFamily",       m_appearance.fontFamily},
        {"editorFontSizePt", m_appearance.editorFontSizePt},
        {"ligatures",        m_appearance.ligatures},
        {"tabSize",          m_appearance.tabSize},
        {"insertSpaces",     m_appearance.insertSpaces}
    };

    std::ofstream out(path, std::ios::trunc);
    if (!out.is_open()) {
        appendToOutput("[Settings] Failed to write " + path.string() + "\n",
                       "Output", OutputSeverity::Error);
        return;
    }
    out << j.dump(2);

    appendToOutput("[Settings] Saved to " + path.string() + "\n",
                   "Output", OutputSeverity::Info);
}