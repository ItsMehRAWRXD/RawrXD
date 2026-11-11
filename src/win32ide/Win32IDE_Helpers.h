// Win32IDE_Helpers.h
// Helper functions for Win32IDE menu handlers

#pragma once
#include <windows.h>
#include <string>

// =============================================================================
// DOCUMENT PATH HELPERS
// =============================================================================

// Get the path of the currently active document
std::wstring GetActiveDocumentPath();

// Set the active document path
void SetActiveDocumentPath(const wchar_t* path);

// Get the current project name
std::wstring GetCurrentProjectName();

// Set the current project name
void SetCurrentProjectName(const wchar_t* name);

// =============================================================================
// STATUS BAR HELPERS
// =============================================================================

// Set status bar text
void SetStatusBarText(const wchar_t* text);

// Set progress percentage (0-100)
void SetStatusBarProgress(int percent);

// Clear status bar to default state
void ClearStatusBar();

// =============================================================================
// OUTPUT WINDOW HELPERS
// =============================================================================

// Append text to output window
void AppendOutputText(const wchar_t* text);

// Clear output window
void ClearOutputWindow();

// Append ANSI text to output window (converts to wide)
void AppendOutputTextA(const char* text);

// =============================================================================
// MENU HELPERS
// =============================================================================

// Enable or disable a menu item by ID
void EnableMenuItemByID(int id, BOOL enable);

// Check or uncheck a menu item by ID
void CheckMenuItemByID(int id, BOOL checked);

// =============================================================================
// EDITOR HELPERS
// =============================================================================

// Get text from editor
std::wstring GetEditorText();

// Set text in editor
void SetEditorText(const wchar_t* text);

// =============================================================================
// UTILITY HELPERS
// =============================================================================

// Check if a project is currently open
bool IsProjectOpen();

// Check if build output (.exe) exists
bool IsBuildOutputAvailable();

// Show error message box
void ShowErrorMessage(const wchar_t* message);

// Show info message box
void ShowInfoMessage(const wchar_t* message);

// Ask yes/no question, returns true if yes
bool AskYesNoQuestion(const wchar_t* question);

// =============================================================================
// WINDOW CREATION HELPERS
// =============================================================================

// Create output window
HWND CreateOutputWindow(HWND hWndParent, HINSTANCE hInstance);

// Create project panel
HWND CreateProjectPanel(HWND hWndParent, HINSTANCE hInstance);

// =============================================================================
// INITIALIZATION
// =============================================================================

// Initialize helper system
void InitializeWin32IDEHelpers(HWND hWndMain, HWND hWndEditor, HWND hWndStatusBar, HINSTANCE hInstance);
