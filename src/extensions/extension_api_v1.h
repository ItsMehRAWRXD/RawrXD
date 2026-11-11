// ============================================================================
// extension_api_v1.h — RawrXD Extension API Version 1.0
// ============================================================================
// Core interfaces for third-party extension development
// ============================================================================

#pragma once

#include <string>
#include <functional>
#include <memory>
#include <vector>
#include <unordered_map>

namespace RawrXD {
namespace Extensions {

// ============================================================================
// Extension Metadata
// ============================================================================

struct ExtensionManifest {
    std::string id;              // Unique identifier (e.g., "publisher.extension")
    std::string name;            // Human-readable name
    std::string version;         // SemVer version (e.g., "1.0.0")
    std::string description;     // Short description
    std::string publisher;       // Publisher name
    std::string homepage;        // Optional homepage URL
    std::vector<std::string> categories;  // e.g., ["Programming Languages", "Linters"]
    std::vector<std::string> engines;     // Required engines (e.g., ["powershell", "masm"])
};

// ============================================================================
// Extension Lifecycle
// ============================================================================

enum class ExtensionState {
    Unloaded,
    Loading,
    Active,
    Deactivated,
    Error
};

class IExtension {
public:
    virtual ~IExtension() = default;
    
    // Lifecycle methods
    virtual bool initialize() = 0;
    virtual void shutdown() = 0;
    virtual void activate() = 0;
    virtual void deactivate() = 0;
    
    // Metadata
    virtual const ExtensionManifest& getManifest() const = 0;
    virtual ExtensionState getState() const = 0;
};

// ============================================================================
// Editor Integration Points
// ============================================================================

class IEditor {
public:
    virtual ~IEditor() = default;
    
    // Document operations
    virtual std::string getActiveDocument() const = 0;
    virtual std::string getDocumentContent(const std::string& path) const = 0;
    virtual void setDocumentContent(const std::string& path, const std::string& content) = 0;
    virtual void insertText(const std::string& text) = 0;
    virtual void replaceSelection(const std::string& text) = 0;
    
    // Cursor operations
    virtual int getCursorLine() const = 0;
    virtual int getCursorColumn() const = 0;
    virtual void setCursorPosition(int line, int column) = 0;
    
    // Selection operations
    virtual std::string getSelectedText() const = 0;
    virtual void selectLine(int line) = 0;
    virtual void selectAll() = 0;
    
    // Viewport operations
    virtual int getFirstVisibleLine() const = 0;
    virtual int getLastVisibleLine() const = 0;
    virtual void scrollToLine(int line) = 0;
};

// ============================================================================
// Language Server Integration
// ============================================================================

class ILanguageServer {
public:
    virtual ~ILanguageServer() = default;
    
    // Completion
    struct CompletionItem {
        std::string label;
        std::string kind;      // "function", "variable", "class", etc.
        std::string detail;    // Optional detail
        std::string documentation;
        std::string insertText;
        int sortText = 0;
    };
    
    virtual std::vector<CompletionItem> requestCompletions(
        const std::string& filePath,
        int line,
        int column) = 0;
    
    // Hover
    struct HoverInfo {
        std::string contents;
        std::string language;  // e.g., "cpp", "markdown"
    };
    
    virtual HoverInfo requestHover(
        const std::string& filePath,
        int line,
        int column) = 0;
    
    // Go to Definition
    struct Location {
        std::string filePath;
        int line;
        int column;
    };
    
    virtual std::vector<Location> goToDefinition(
        const std::string& filePath,
        int line,
        int column) = 0;
    
    // Find References
    virtual std::vector<Location> findReferences(
        const std::string& symbol,
        const std::string& filePath,
        int line,
        int column) = 0;
    
    // Diagnostics
    struct Diagnostic {
        std::string message;
        int severity;  // 1=error, 2=warning, 3=info
        int line;
        int column;
        std::string source;
    };
    
    virtual std::vector<Diagnostic> getDiagnostics(const std::string& filePath) = 0;
};

// ============================================================================
// Terminal Integration
// ============================================================================

class ITerminal {
public:
    virtual ~ITerminal() = default;
    
    virtual void executeCommand(const std::string& command) = 0;
    virtual std::string executeAndGetOutput(const std::string& command) = 0;
    virtual void sendText(const std::string& text) = 0;
    virtual void clear() = 0;
    virtual std::string getWorkingDirectory() const = 0;
    virtual void setWorkingDirectory(const std::string& path) = 0;
};

// ============================================================================
// File System Integration
// ============================================================================

class IFileSystem {
public:
    virtual ~IFileSystem() = default;
    
    virtual bool fileExists(const std::string& path) const = 0;
    virtual bool directoryExists(const std::string& path) const = 0;
    virtual std::string readFile(const std::string& path) const = 0;
    virtual void writeFile(const std::string& path, const std::string& content) = 0;
    virtual void deleteFile(const std::string& path) = 0;
    virtual void createDirectory(const std::string& path) = 0;
    virtual std::vector<std::string> listDirectory(const std::string& path) const = 0;
    virtual std::string getAbsolutePath(const std::string& relativePath) const = 0;
    virtual std::string joinPaths(const std::string& path1, const std::string& path2) const = 0;
};

// ============================================================================
// UI Integration
// ============================================================================

class IStatusBar {
public:
    virtual ~IStatusBar() = default;
    
    virtual void showMessage(const std::string& message, int timeout = 3000) = 0;
    virtual void showWarning(const std::string& message, int timeout = 5000) = 0;
    virtual void showError(const std::string& message, int timeout = 10000) = 0;
    virtual void setProgress(double percentage) = 0;
    virtual void clearProgress() = 0;
};

class IOutputChannel {
public:
    virtual ~IOutputChannel() = default;
    
    virtual void append(const std::string& message) = 0;
    virtual void appendLine(const std::string& message) = 0;
    virtual void clear() = 0;
    virtual void show() = 0;
    virtual void hide() = 0;
};

// ============================================================================
// Configuration Integration
// ============================================================================

class IConfiguration {
public:
    virtual ~IConfiguration() = default;
    
    template<typename T>
    virtual T getValue(const std::string& key, const T& defaultValue) const = 0;
    
    virtual void setValue(const std::string& key, const std::string& value) = 0;
    virtual bool hasKey(const std::string& key) const = 0;
    virtual void removeKey(const std::string& key) = 0;
};

// ============================================================================
// Extension Host API
// ============================================================================

class IExtensionHost {
public:
    virtual ~IExtensionHost() = default;
    
    // Core services
    virtual IEditor* getEditor() = 0;
    virtual ILanguageServer* getLanguageServer() = 0;
    virtual ITerminal* getTerminal() = 0;
    virtual IFileSystem* getFileSystem() = 0;
    virtual IStatusBar* getStatusBar() = 0;
    virtual IOutputChannel* createOutputChannel(const std::string& name) = 0;
    virtual IConfiguration* getConfiguration() = 0;
    
    // Extension management
    virtual bool registerExtension(std::shared_ptr<IExtension> extension) = 0;
    virtual bool unregisterExtension(const std::string& extensionId) = 0;
    virtual IExtension* getExtension(const std::string& extensionId) = 0;
    virtual std::vector<std::shared_ptr<IExtension>> getAllExtensions() = 0;
    
    // Commands
    using CommandCallback = std::function<void(const std::vector<std::string>&)>;
    virtual bool registerCommand(const std::string& commandId, CommandCallback callback) = 0;
    virtual bool unregisterCommand(const std::string& commandId) = 0;
    virtual void executeCommand(const std::string& commandId, const std::vector<std::string>& args = {}) = 0;
    
    // Events
    using EventCallback = std::function<void()>;
    virtual void onDocumentOpened(EventCallback callback) = 0;
    virtual void onDocumentClosed(EventCallback callback) = 0;
    virtual void onDocumentSaved(EventCallback callback) = 0;
    virtual void onCursorMoved(EventCallback callback) = 0;
    virtual void onSelectionChanged(EventCallback callback) = 0;
};

// ============================================================================
// Extension Entry Point
// ============================================================================

// Extensions must export this function
extern "C" __declspec(dllexport)
IExtension* CreateExtension(IExtensionHost* host);

extern "C" __declspec(dllexport)
void DestroyExtension(IExtension* extension);

} // namespace Extensions
} // namespace RawrXD
