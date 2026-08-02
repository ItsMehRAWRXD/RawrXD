# RawrXD Extension API Reference

**Version:** 1.0  
**Generated:** 2026-08-02

---

## Core Interfaces

### IExtension

Base interface for all extensions.

```cpp
class IExtension {
public:
    virtual ~IExtension() = default;
    
    // Lifecycle
    virtual bool initialize() = 0;
    virtual void shutdown() = 0;
    virtual void activate() = 0;
    virtual void deactivate() = 0;
    
    // Metadata
    virtual const ExtensionManifest& getManifest() const = 0;
    virtual ExtensionState getState() const = 0;
};
```

#### Methods

- **`initialize()`** → `bool`  
  Called when extension is loaded. Return `true` to continue loading.

- **`shutdown()`** → `void`  
  Called when RawrXD exits. Clean up resources.

- **`activate()`** → `void`  
  Called when extension is activated. Register commands, subscribe to events.

- **`deactivate()`** → `void`  
  Called when extension is deactivated. Unregister commands, cleanup.

- **`getManifest()`** → `const ExtensionManifest&`  
  Return extension metadata.

- **`getState()`** → `ExtensionState`  
  Return current extension state.

---

### IExtensionHost

Main interface for interacting with RawrXD IDE.

```cpp
class IExtensionHost {
public:
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
    
    // Commands
    virtual bool registerCommand(const std::string& commandId, CommandCallback callback) = 0;
    virtual bool unregisterCommand(const std::string& commandId) = 0;
    virtual void executeCommand(const std::string& commandId, const std::vector<std::string>& args = {}) = 0;
    
    // Events
    virtual void onDocumentOpened(EventCallback callback) = 0;
    virtual void onDocumentClosed(EventCallback callback) = 0;
    virtual void onDocumentSaved(EventCallback callback) = 0;
    virtual void onCursorMoved(EventCallback callback) = 0;
    virtual void onSelectionChanged(EventCallback callback) = 0;
};
```

---

## Service Interfaces

### IEditor

Provides access to the active editor.

#### Methods

- **`getActiveDocument()`** → `std::string`  
  Get path of active document.

- **`getDocumentContent(path)`** → `std::string`  
  Get document content.

- **`setDocumentContent(path, content)`** → `void`  
  Set document content.

- **`insertText(text)`** → `void`  
  Insert text at cursor position.

- **`replaceSelection(text)`** → `void`  
  Replace selected text.

- **`getCursorLine()`** → `int`  
  Get current cursor line (0-based).

- **`getCursorColumn()`** → `int`  
  Get current cursor column (0-based).

- **`setCursorPosition(line, column)`** → `void`  
  Move cursor to position.

- **`getSelectedText()`** → `std::string`  
  Get selected text.

- **`selectLine(line)`** → `void`  
  Select entire line.

- **`selectAll()`** → `void`  
  Select all text.

---

### ILanguageServer

Provides language intelligence features.

#### Methods

- **`requestCompletions(filePath, line, column)`** → `std::vector<CompletionItem>`  
  Get code completions.

- **`requestHover(filePath, line, column)`** → `HoverInfo`  
  Get hover information.

- **`goToDefinition(filePath, line, column)`** → `std::vector<Location>`  
  Find symbol definition.

- **`findReferences(symbol, filePath, line, column)`** → `std::vector<Location>`  
  Find all references.

- **`getDiagnostics(filePath)`** → `std::vector<Diagnostic>`  
  Get diagnostics (errors, warnings).

---

### ITerminal

Provides terminal access.

#### Methods

- **`executeCommand(command)`** → `void`  
  Execute command in terminal.

- **`executeAndGetOutput(command)`** → `std::string`  
  Execute and return output.

- **`sendText(text)`** → `void`  
  Send text to terminal.

- **`clear()`** → `void`  
  Clear terminal.

- **`getWorkingDirectory()`** → `std::string`  
  Get current directory.

- **`setWorkingDirectory(path)`** → `void`  
  Set working directory.

---

### IFileSystem

Provides file system access.

#### Methods

- **`fileExists(path)`** → `bool`  
  Check if file exists.

- **`directoryExists(path)`** → `bool`  
  Check if directory exists.

- **`readFile(path)`** → `std::string`  
  Read file content.

- **`writeFile(path, content)`** → `void`  
  Write file content.

- **`deleteFile(path)`** → `void`  
  Delete file.

- **`createDirectory(path)`** → `void`  
  Create directory.

- **`listDirectory(path)`** → `std::vector<std::string>`  
  List directory contents.

- **`getAbsolutePath(relativePath)`** → `std::string`  
  Convert to absolute path.

- **`joinPaths(path1, path2)`** → `std::string`  
  Join two paths.

---

### IStatusBar

Provides status bar access.

#### Methods

- **`showMessage(message, timeout)`** → `void`  
  Show info message.

- **`showWarning(message, timeout)`** → `void`  
  Show warning message.

- **`showError(message, timeout)`** → `void`  
  Show error message.

- **`setProgress(percentage)`** → `void`  
  Set progress indicator (0.0-1.0).

- **`clearProgress()`** → `void`  
  Clear progress indicator.

---

### IOutputChannel

Provides output channel for logging.

#### Methods

- **`append(message)`** → `void`  
  Append text.

- **`appendLine(message)`** → `void`  
  Append line with newline.

- **`clear()`** → `void`  
  Clear output.

- **`show()`** → `void`  
  Show output panel.

- **`hide()`** → `void`  
  Hide output panel.

---

### IConfiguration

Provides configuration access.

#### Methods

- **`getValue<T>(key, defaultValue)`** → `T`  
  Get typed value.

- **`setValue(key, value)`** → `void`  
  Set value.

- **`hasKey(key)`** → `bool`  
  Check if key exists.

- **`removeKey(key)`** → `void`  
  Remove key.

---

## Data Structures

### ExtensionManifest

```cpp
struct ExtensionManifest {
    std::string id;              // "publisher.extension"
    std::string name;            // "My Extension"
    std::string version;         // "1.0.0"
    std::string description;     // "Description"
    std::string publisher;       // "Publisher Name"
    std::string homepage;        // "https://..."
    std::vector<std::string> categories;
    std::vector<std::string> engines;
};
```

### CompletionItem

```cpp
struct CompletionItem {
    std::string label;           // "myFunction"
    std::string kind;            // "function", "variable", etc.
    std::string detail;          // Optional detail
    std::string documentation;   // Markdown docs
    std::string insertText;      // Text to insert
    int sortText = 0;            // Sort order
};
```

### Diagnostic

```cpp
struct Diagnostic {
    std::string message;         // Error/warning message
    int severity;                // 1=error, 2=warning, 3=info
    int line;                    // Line number (0-based)
    int column;                  // Column number (0-based)
    std::string source;          // "my-extension"
};
```

### Location

```cpp
struct Location {
    std::string filePath;        // File path
    int line;                    // Line number (0-based)
    int column;                  // Column number (0-based)
};
```

---

## Entry Points

Extensions must export two functions:

```cpp
extern "C" __declspec(dllexport)
IExtension* CreateExtension(IExtensionHost* host);

extern "C" __declspec(dllexport)
void DestroyExtension(IExtension* extension);
```

---

## Examples

### Register Command

```cpp
host->registerCommand("myExtension.hello", [](const std::vector<std::string>& args) {
    host->getStatusBar()->showMessage("Hello!", 3000);
});
```

### Subscribe to Event

```cpp
host->onDocumentSaved([]() {
    std::cout << "Document saved!" << std::endl;
});
```

### Execute Command

```cpp
host->executeCommand("workbench.action.files.save");
```

### Get Configuration

```cpp
auto* config = host->getConfiguration();
bool enabled = config->getValue<bool>("myExtension.enabled", true);
```

---

## See Also

- [Developer Guide](developer-guide.md)
- [Sample Extensions](https://github.com/ItsMehRAWRXD/rawrxd-samples)
