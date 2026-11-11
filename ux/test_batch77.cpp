// test_batch77.cpp — Compilation test for Batch 77 (UX Polish)
#include "command_palette.hpp"
#include "keyboard_shortcuts.hpp"
#include "docking.hpp"
#include "theme_engine.hpp"
#include "settings_ui.hpp"
#include "onboarding.hpp"

int main() {
    // Test Command Palette
    auto& palette = RawrXD::UX::CommandPalette::Get();
    palette.RegisterBuiltinCommands();
    auto results = palette.Search("build");
    palette.Execute("file.new");
    auto recent = palette.GetRecentCommands(5);

    // Test Keyboard Shortcuts
    auto& shortcuts = RawrXD::UX::KeyboardShortcutManager::Get();
    RawrXD::UX::ShortcutEntry entry;
    entry.key = RawrXD::UX::KeyboardShortcutManager::ParseKeyString("Ctrl+Shift+P");
    entry.commandId = "view.commandPalette";
    entry.label = "Show Command Palette";
    shortcuts.RegisterShortcut(entry);
    auto cmd = shortcuts.GetCommandForKey(RawrXD::UX::KeyboardShortcutManager::ParseKeyString("Ctrl+Shift+P"));
    auto keys = shortcuts.GetKeysForCommand("view.commandPalette");

    // Test Docking
    auto& docking = RawrXD::UX::DockingManager::Get();
    RawrXD::UX::PanelDefinition explorer;
    explorer.id = "explorer";
    explorer.title = "Explorer";
    explorer.defaultPosition = RawrXD::UX::DockPosition::Left;
    docking.RegisterPanel(explorer);
    auto* panel = docking.OpenPanel("explorer");
    docking.FocusPanel("explorer");
    docking.SaveLayout("default");
    docking.LoadLayout("default");

    // Test Theme Engine
    auto& themes = RawrXD::UX::ThemeEngine::Get();
    themes.RegisterBuiltinThemes();
    themes.SetTheme("dark-default");
    auto bg = themes.GetColor("editor.background");
    auto fg = themes.GetColor("editor.foreground");
    auto tokenColor = themes.GetTokenColor("keyword");
    auto allThemes = themes.ListThemes();

    // Test Settings UI
    auto& settings = RawrXD::UX::SettingsUIManager::Get();
    settings.RegisterBuiltinSettings();
    settings.SetValue("editor.fontSize", "16");
    auto fontSize = settings.GetValue("editor.fontSize");
    auto editorSettings = settings.GetSettingsByCategory("editor");
    auto searchResults = settings.SearchSettings("font");

    // Test Onboarding
    auto& onboarding = RawrXD::UX::OnboardingManager::Get();
    onboarding.Initialize();
    onboarding.AddRecentProject("RawrXD", "d:\\rawrxd");
    auto welcome = onboarding.GetWelcomeContent();
    auto tip = onboarding.GetTipOfTheDay();
    onboarding.NextStep();
    onboarding.CompleteOnboarding();

    return 0;
}
