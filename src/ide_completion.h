#pragma once

#include <windows.h>
#include <string>
#include <functional>

namespace IDECompletion {

// Completion popup context
struct PopupContext {
    HWND hParentWnd;
    int x, y;                      // Screen coordinates
    std::string current_line;      // Text before cursor
    std::string model;             // Selected model (legacy, kept for compatibility)
    std::function<void(const std::string&)> on_select; // Callback when user accepts
};

// Initialize IDE completion system using RawrXD native inference engine
void InitializeCompletionEngine(const std::string& default_model = "");

// Initialize with a specific model path (preferred)
void InitializeCompletionEngineWithModel(const std::string& model_path);

// Request completions for current editor position
// This triggers async query to RawrXD native inference engine
void RequestCompletion(const PopupContext& ctx);

// Cancel pending completion request
void CancelCompletion();

// Show completion popup
void ShowCompletionPopup(const PopupContext& ctx, const std::string& suggestion);

// Hide completion popup
void HideCompletionPopup();

// Set model to use for completions (legacy, kept for API compatibility)
void SetCompletionModel(const std::string& model);

// Get status of native completion engine
bool IsCompletionEngineReady();

} // namespace IDECompletion
