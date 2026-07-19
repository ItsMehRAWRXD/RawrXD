#pragma once
#include <string>

namespace IDE {

// Clipboard utility for text operations
class Clipboard {
public:
    static void Init() {} // No initialization needed for Win32 clipboard
    
    // Set text to clipboard
    static bool SetText(const char* text);
    static bool SetText(const std::string& text) { return SetText(text.c_str()); }
    
    // Get text from clipboard
    static std::string GetText();
    
    // Check if clipboard has text
    static bool HasText();
    
    // Clear clipboard
    static bool Clear();
};

} // namespace IDE
