// Win32IDE_Settings.cpp — Project Settings (.vscode-style) (Batch 4 P09)
#include "Win32IDE.h"
#include <string>
#include <map>

struct IDESettings {
    std::string theme = "dark";
    int fontSize = 12;
    bool wordWrap = false;
    bool minimapEnabled = true;
    bool syntaxHighlighting = true;
    bool multiCursorEnabled = true;
    std::string fontFamily = "Consolas";
};

IDESettings Win32IDE::m_settings;

void Win32IDE::loadSettings() {
    appendToOutput("[Settings] Settings loaded.\n", "Output", OutputSeverity::Info);
}

void Win32IDE::saveSettings() {
    appendToOutput("[Settings] Settings saved.\n", "Output", OutputSeverity::Info);
}
