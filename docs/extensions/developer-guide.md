# RawrXD Extension Developer Guide

**Version:** 1.0  
**Last Updated:** 2026-08-02

---

## 🚀 Quick Start

### Prerequisites

- C++17 or later
- RawrXD IDE installed
- Basic knowledge of C++ and IDE extensions

### Create Your First Extension

1. **Create Extension Directory**
   ```bash
   mkdir my-extension
   cd my-extension
   ```

2. **Create Extension Manifest** (`extension.json`)
   ```json
   {
     "id": "publisher.hello-world",
     "name": "Hello World",
     "version": "1.0.0",
     "description": "My first RawrXD extension",
     "publisher": "YourName",
     "engines": ["cpp"],
     "main": "extension.cpp"
   }
   ```

3. **Implement Extension** (`extension.cpp`)
   ```cpp
   #include <rawrxd/extension_api_v1.h>
   
   using namespace RawrXD::Extensions;
   
   class HelloWorldExtension : public IExtension {
   private:
       IExtensionHost* host_;
       ExtensionManifest manifest_;
       
   public:
       HelloWorldExtension(IExtensionHost* host) : host_(host) {
           manifest_.id = "publisher.hello-world";
           manifest_.name = "Hello World";
           manifest_.version = "1.0.0";
           manifest_.description = "My first RawrXD extension";
           manifest_.publisher = "YourName";
       }
       
       bool initialize() override {
           // Register commands
           host_->registerCommand("helloWorld.sayHello", [](const std::vector<std::string>& args) {
               std::cout << "Hello from RawrXD!" << std::endl;
           });
           
           return true;
       }
       
       void shutdown() override {}
       void activate() override {}
       void deactivate() override {}
       
       const ExtensionManifest& getManifest() const override {
           return manifest_;
       }
       
       ExtensionState getState() const override {
           return ExtensionState::Active;
       }
   };
   
   // Entry point
   extern "C" __declspec(dllexport)
   IExtension* CreateExtension(IExtensionHost* host) {
       return new HelloWorldExtension(host);
   }
   
   extern "C" __declspec(dllexport)
   void DestroyExtension(IExtension* extension) {
       delete extension;
   }
   ```

4. **Build Extension**
   ```bash
   cl /LD extension.cpp /I"C:\RawrXD\include" /link /OUT:hello-world.dll
   ```

5. **Install Extension**
   ```bash
   rawrxd --install-extension hello-world.dll
   ```

6. **Test Extension**
   - Open RawrXD IDE
   - Press `Ctrl+Shift+P`
   - Type "Hello World: Say Hello"
   - Execute command

---

## 📚 Extension API Reference

### Extension Lifecycle

```cpp
class IExtension {
    virtual bool initialize() = 0;      // Called when extension is loaded
    virtual void shutdown() = 0;        // Called when RawrXD exits
    virtual void activate() = 0;        // Called when extension is activated
    virtual void deactivate() = 0;      // Called when extension is deactivated
};
```

### Available Services

#### Editor Service

```cpp
class IEditor {
    std::string getActiveDocument() const;
    std::string getDocumentContent(const std::string& path) const;
    void setDocumentContent(const std::string& path, const std::string& content);
    void insertText(const std::string& text);
    void replaceSelection(const std::string& text);
    int getCursorLine() const;
    int getCursorColumn() const;
    void setCursorPosition(int line, int column);
    std::string getSelectedText() const;
    void selectLine(int line);
    void selectAll();
};
```

#### Language Server Service

```cpp
class ILanguageServer {
    std::vector<CompletionItem> requestCompletions(
        const std::string& filePath, int line, int column);
    HoverInfo requestHover(
        const std::string& filePath, int line, int column);
    std::vector<Location> goToDefinition(
        const std::string& filePath, int line, int column);
    std::vector<Location> findReferences(
        const std::string& symbol, const std::string& filePath,
        int line, int column);
    std::vector<Diagnostic> getDiagnostics(const std::string& filePath);
};
```

#### Terminal Service

```cpp
class ITerminal {
    void executeCommand(const std::string& command);
    std::string executeAndGetOutput(const std::string& command);
    void sendText(const std::string& text);
    void clear();
    std::string getWorkingDirectory() const;
    void setWorkingDirectory(const std::string& path);
};
```

#### File System Service

```cpp
class IFileSystem {
    bool fileExists(const std::string& path) const;
    bool directoryExists(const std::string& path) const;
    std::string readFile(const std::string& path) const;
    void writeFile(const std::string& path, const std::string& content);
    void deleteFile(const std::string& path);
    void createDirectory(const std::string& path);
    std::vector<std::string> listDirectory(const std::string& path) const;
    std::string getAbsolutePath(const std::string& relativePath) const;
    std::string joinPaths(const std::string& path1, const std::string& path2) const;
};
```

### Commands

Register custom commands:

```cpp
host->registerCommand("myExtension.myCommand", 
    [](const std::vector<std::string>& args) {
        // Command implementation
    });
```

Execute commands:

```cpp
host->executeCommand("myExtension.myCommand", {"arg1", "arg2"});
```

### Events

Subscribe to events:

```cpp
host->onDocumentOpened([]() {
    std::cout << "Document opened!" << std::endl;
});

host->onCursorMoved([]() {
    // Cursor moved
});
```

---

## 🎨 UI Integration

### Status Bar Messages

```cpp
auto* statusBar = host->getStatusBar();
statusBar->showMessage("Operation completed", 3000);
statusBar->showWarning("Warning message", 5000);
statusBar->showError("Error occurred", 10000);
```

### Output Channels

```cpp
auto* output = host->createOutputChannel("My Extension");
output->appendLine("Starting operation...");
output->appendLine("Processing...");
output->show();
```

---

## 📦 Publishing Extensions

### Package Extension

```bash
rawrxd --package-extension my-extension/
```

This creates `my-extension.vsix` file.

### Publish to Marketplace

```bash
rawrxd --publish-extension my-extension.vsix --token YOUR_TOKEN
```

### Update Extension

```bash
rawrxd --update-extension my-extension/
```

---

## 🧪 Testing Extensions

### Unit Tests

```cpp
#include <rawrxd/extension_test.h>

TEST(HelloWorldExtension, SayHello) {
    auto* host = createTestHost();
    HelloWorldExtension ext(host);
    
    EXPECT_TRUE(ext.initialize());
    EXPECT_EQ(ext.getManifest().id, "publisher.hello-world");
}
```

### Integration Tests

```bash
rawrxd --test-extension my-extension/
```

---

## 🔧 Debugging Extensions

### Enable Extension Debugging

```json
{
  "extension.debug": true,
  "extension.logLevel": "debug"
}
```

### View Extension Logs

```bash
rawrxd --show-extension-logs publisher.hello-world
```

---

## 📝 Best Practices

1. **Performance**
   - Avoid blocking the UI thread
   - Use async operations for long-running tasks
   - Cache frequently accessed data

2. **Security**
   - Validate all user inputs
   - Don't execute arbitrary code
   - Use sandbox for untrusted operations

3. **Compatibility**
   - Specify minimum RawrXD version in manifest
   - Handle API versioning gracefully
   - Test on multiple RawrXD versions

4. **User Experience**
   - Provide clear error messages
   - Show progress for long operations
   - Respect user settings

---

## 📚 Resources

- [API Reference](api-reference.md)
- [Sample Extensions](https://github.com/ItsMehRAWRXD/rawrxd-samples)
- [Community Forum](https://community.rawrxd.com)
- [Discord Server](https://discord.gg/rawrxd)

---

## ❓ FAQ

**Q: How do I distribute my extension?**  
A: Package it with `--package-extension` and publish to marketplace or share `.vsix` file directly.

**Q: Can I use external libraries?**  
A: Yes, bundle them with your extension or use RawrXD's built-in libraries.

**Q: How do I handle updates?**  
A: Implement version checking in `initialize()` and notify users of updates.

**Q: Can I add custom UI?**  
A: Yes, use the UI integration APIs to add views, panels, and dialogs.

---

## 🤝 Contributing

We welcome extension contributions! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.
