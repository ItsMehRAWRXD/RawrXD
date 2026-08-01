#pragma once

// ============================================================================
// IMultiFileSearchWidget Interface
// Abstract interface for multi-file search functionality
// Replaces direct extern function calls with proper interface abstraction
// ============================================================================

class IMultiFileSearchWidget {
public:
    virtual ~IMultiFileSearchWidget() = default;
    
    // Show the search dialog
    virtual void ShowDialog() = 0;
    
    // Set the project root directory for searching
    virtual void SetProjectRoot(const char* rootPath) = 0;
    
    // Set callback for when dialog should be shown
    virtual void SetShowCallback(void (*callback)(void*), void* context) = 0;
    
    // Check if search is currently running
    virtual bool IsSearching() const = 0;
    
    // Cancel ongoing search
    virtual void CancelSearch() = 0;
};

// Factory function to create the widget implementation
// Returns nullptr if widget is not available
IMultiFileSearchWidget* CreateMultiFileSearchWidget();

// Singleton accessor for the global widget instance
IMultiFileSearchWidget* GetMultiFileSearchWidget();

// Destroy the widget instance (call on shutdown)
void DestroyMultiFileSearchWidget();
