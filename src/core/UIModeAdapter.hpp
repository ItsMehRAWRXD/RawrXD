#pragma once
#include "IIDEInterface.hpp"
#include <type_traits>
#include <cstdio>
#include <cstdlib>

namespace RawrXD {

// UI Mode enumeration
enum class UIMode : uint32_t {
    GUI = 1,
    CLI = 2,
    Headless = 3
};

// ============================================================================
// UIModeAdapter - Compile-Time Mode Selection
// ============================================================================
// Uses template parameters and if constexpr for zero-overhead abstraction.
// Inactive branches are stripped at compile time.
// ============================================================================

template<UIMode Mode>
class UIModeAdapter {
public:
    static constexpr UIMode CurrentMode = Mode;
    
    // Check if current mode is GUI
    static constexpr bool IsGUI() noexcept { return Mode == UIMode::GUI; }
    
    // Check if current mode is CLI
    static constexpr bool IsCLI() noexcept { return Mode == UIMode::CLI; }
    
    // Check if current mode is Headless
    static constexpr bool IsHeadless() noexcept { return Mode == UIMode::Headless; }
    
    // Get mode name as string_view
    static constexpr std::string_view GetModeName() noexcept {
        if constexpr (Mode == UIMode::GUI) return "GUI";
        else if constexpr (Mode == UIMode::CLI) return "CLI";
        else if constexpr (Mode == UIMode::Headless) return "Headless";
        else return "Unknown";
    }
};

// ============================================================================
// Mode-Specific Component Templates
// ============================================================================

template<UIMode Mode>
class ChatPanelAdapter {
public:
    void Render() noexcept {
        if constexpr (Mode == UIMode::GUI) {
            RenderRichText();
        } else if constexpr (Mode == UIMode::CLI) {
            RenderPlainText();
        } else if constexpr (Mode == UIMode::Headless) {
            // No rendering in headless mode
        }
    }
    
    void AddMessage(const char* sender, const char* message) noexcept {
        if constexpr (Mode == UIMode::GUI) {
            // Add to rich text control
            AddMessageToRichEdit(sender, message);
        } else if constexpr (Mode == UIMode::CLI) {
            // Print to stdout
            printf("[%s]: %s\n", sender, message);
        } else if constexpr (Mode == UIMode::Headless) {
            // Log to file or ignore
        }
    }
    
    void Clear() noexcept {
        if constexpr (Mode == UIMode::GUI) {
            ClearRichEdit();
        } else if constexpr (Mode == UIMode::CLI) {
            // Clear screen or add separator
            printf("\n---\n\n");
        }
    }

private:
    // GUI implementations (stubs)
    void RenderRichText() noexcept {}
    void RenderPlainText() noexcept {}
    void AddMessageToRichEdit(const char* sender, const char* message) noexcept {}
    void ClearRichEdit() noexcept {}
};

template<UIMode Mode>
class ModelManagerAdapter {
public:
    void ShowModelDialog() noexcept {
        if constexpr (Mode == UIMode::GUI) {
            ShowModelDialogGUI();
        } else if constexpr (Mode == UIMode::CLI) {
            ShowModelMenuCLI();
        } else if constexpr (Mode == UIMode::Headless) {
            // No UI in headless - use API only
        }
    }
    
    void UpdateStatus(const char* modelName, float progress) noexcept {
        if constexpr (Mode == UIMode::GUI) {
            UpdateProgressBar(progress);
            UpdateStatusLabel(modelName);
        } else if constexpr (Mode == UIMode::CLI) {
            // Print progress
            printf("\rLoading %s: %.1f%%", modelName, progress * 100);
            fflush(stdout);
        }
    }
    
    void ShowError(const char* message) noexcept {
        if constexpr (Mode == UIMode::GUI) {
            ShowMessageBox(message);
        } else if constexpr (Mode == UIMode::CLI) {
            fprintf(stderr, "Error: %s\n", message);
        } else if constexpr (Mode == UIMode::Headless) {
            // Log error
        }
    }

private:
    void ShowModelDialogGUI() noexcept {}
    void ShowModelMenuCLI() noexcept {}
    void UpdateProgressBar(float progress) noexcept {}
    void UpdateStatusLabel(const char* text) noexcept {}
    void ShowMessageBox(const char* text) noexcept {}
};

template<UIMode Mode>
class FileBrowserAdapter {
public:
    void OpenFileDialog() noexcept {
        if constexpr (Mode == UIMode::GUI) {
            ShowFileDialogGUI();
        } else if constexpr (Mode == UIMode::CLI) {
            // CLI uses command-line arguments
            printf("Use: open <filepath>\n");
        }
    }
    
    void Refresh() noexcept {
        if constexpr (Mode == UIMode::GUI) {
            RefreshTreeView();
        } else if constexpr (Mode == UIMode::CLI) {
            // List files
            printf("Files in current directory:\n");
        }
    }

private:
    void ShowFileDialogGUI() noexcept {}
    void RefreshTreeView() noexcept {}
};

// ============================================================================
// Runtime Mode Detection
// ============================================================================

// Detect mode from command-line arguments
inline UIMode DetectModeFromArgs(int argc, wchar_t* argv[]) noexcept {
    for (int i = 1; i < argc; ++i) {
        if (argv[i]) {
            // Check for --headless flag
            if (wcscmp(argv[i], L"--headless") == 0 ||
                wcscmp(argv[i], L"--server") == 0) {
                return UIMode::Headless;
            }
            // Check for --cli flag
            if (wcscmp(argv[i], L"--cli") == 0 ||
                wcscmp(argv[i], L"--console") == 0) {
                return UIMode::CLI;
            }
        }
    }
    return UIMode::GUI; // Default
}

// Detect mode from environment
inline UIMode DetectModeFromEnvironment() noexcept {
    const wchar_t* mode = _wgetenv(L"RAWRXD_MODE");
    if (mode) {
        if (wcscmp(mode, L"headless") == 0) return UIMode::Headless;
        if (wcscmp(mode, L"cli") == 0) return UIMode::CLI;
        if (wcscmp(mode, L"gui") == 0) return UIMode::GUI;
    }
    return UIMode::GUI; // Default
}

// ============================================================================
// Mode-Aware Factory
// ============================================================================

template<UIMode Mode>
struct ModeFactory {
    using ChatPanel = ChatPanelAdapter<Mode>;
    using ModelManager = ModelManagerAdapter<Mode>;
    using FileBrowser = FileBrowserAdapter<Mode>;
    using ModeAdapter = UIModeAdapter<Mode>;
};

// Convenience typedefs
using GUIComponents = ModeFactory<UIMode::GUI>;
using CLIComponents = ModeFactory<UIMode::CLI>;
using HeadlessComponents = ModeFactory<UIMode::Headless>;

} // namespace RawrXD
