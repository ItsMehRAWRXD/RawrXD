# RawrXD Advanced - Custom Extensions Guide
## Extending the Sovereign IDE

**Version:** 1.0.0  
**Date:** 2026-07-15  
**Status:** ✅ Complete

---

## Table of Contents

1. [Overview](#overview)
2. [Extension Architecture](#extension-architecture)
3. [Native Extensions](#native-extensions)
4. [Script Extensions](#script-extensions)
5. [Extension API](#extension-api)
6. [UI Extensions](#ui-extensions)
7. [Tool Extensions](#tool-extensions)
8. [Distribution](#distribution)

---

## Overview

This guide covers creating custom extensions for RawrXD, enabling users to add new capabilities to the sovereign IDE.

### Extension Types

| Type | Language | Use Case |
|------|----------|----------|
| Native | C/C++/MASM | Performance-critical |
| Script | Lua/Python | Rapid prototyping |
| UI | C++/QML | Custom interfaces |
| Tool | Any | External integration |

---

## Extension Architecture

### Extension System

```
┌─────────────────────────────────────────┐
│         RawrXD Extension Host           │
├─────────────────────────────────────────┤
│  ┌─────────┐  ┌─────────┐  ┌─────────┐ │
│  │ Native  │  │ Script  │  │   UI    │ │
│  │   Ext   │  │   Ext   │  │   Ext   │ │
│  └────┬────┘  └────┬────┘  └────┬────┘ │
│       │            │            │      │
│       └────────────┴────────────┘      │
│              Extension API              │
├─────────────────────────────────────────┤
│         RawrXD Core Services            │
└─────────────────────────────────────────┘
```

### Extension Lifecycle

```cpp
// Extension lifecycle states
enum ExtensionState {
    EXT_UNLOADED = 0,
    EXT_LOADING = 1,
    EXT_ACTIVE = 2,
    EXT_PAUSED = 3,
    EXT_UNLOADING = 4,
    EXT_ERROR = 5
};

// Extension interface
class IExtension {
public:
    virtual ~IExtension() = default;
    
    // Lifecycle
    virtual bool Initialize(IExtensionHost* host) = 0;
    virtual void Shutdown() = 0;
    
    // Capabilities
    virtual const char* GetName() = 0;
    virtual const char* GetVersion() = 0;
    virtual uint32_t GetCapabilities() = 0;
    
    // Events
    virtual void OnDocumentOpen(const char* path) = 0;
    virtual void OnDocumentClose(const char* path) = 0;
    virtual void OnInferenceComplete(const InferenceResult* result) = 0;
};
```

---

## Native Extensions

### C++ Extension Template

```cpp
// MyExtension.cpp
#include "ExtensionAPI.h"

class MyExtension : public IExtension {
    IExtensionHost* host;
    
public:
    bool Initialize(IExtensionHost* h) override {
        host = h;
        
        // Register commands
        host->RegisterCommand("myext.action", 
                               &MyExtension::OnAction, this);
        
        // Register event handlers
        host->SubscribeEvent(EVENT_DOCUMENT_OPEN,
                            &MyExtension::OnDocumentOpen, this);
        
        return true;
    }
    
    void Shutdown() override {
        // Cleanup
    }
    
    const char* GetName() override { return "MyExtension"; }
    const char* GetVersion() override { return "1.0.0"; }
    
    void OnAction(const CommandArgs* args) {
        // Handle command
        host->ShowMessage("Action executed!");
    }
    
    void OnDocumentOpen(const char* path) {
        // Handle document open
    }
};

// Export factory function
extern "C" __declspec(dllexport) IExtension* CreateExtension() {
    return new MyExtension();
}
```

### MASM Extension

```asm
; MyExtension.asm
; Pure MASM64 extension

.data
extension_name db "MASMExtension", 0
extension_version db "1.0.0", 0

.code

; Extension entry point
Extension_Initialize PROC
    ; Save host pointer
    mov [host_ptr], rcx
    
    ; Register commands
    lea rdx, command_table
    mov rcx, [host_ptr]
    call [rcx].IExtensionHost.RegisterCommands
    
    ; Return success
    mov rax, 1
    ret
Extension_Initialize ENDP

; Command handler
Extension_OnCommand PROC
    ; rcx = command_id
    ; rdx = args
    
    cmp ecx, CMD_MY_ACTION
    jne @@not_handled
    
    ; Execute action
    call ExecuteMyAction
    
    mov rax, 1  ; Handled
    ret
    
@@not_handled:
    xor rax, rax
    ret
Extension_OnCommand ENDP

; Export
PUBLIC Extension_Initialize
PUBLIC Extension_OnCommand

END
```

---

## Script Extensions

### Lua Extension

```lua
-- my_extension.lua
-- RawrXD Lua extension

local M = {}

-- Extension metadata
M.name = "LuaExtension"
M.version = "1.0.0"

-- Initialize
function M.initialize(host)
    M.host = host
    
    -- Register command
    host:register_command("luaext.say_hello", function(args)
        host:show_message("Hello from Lua!")
    end)
    
    -- Subscribe to events
    host:subscribe_event("document_open", function(path)
        print("Document opened: " .. path)
    end)
    
    return true
end

-- Cleanup
function M.shutdown()
    print("LuaExtension shutting down")
end

-- Inference hook
function M.on_inference_complete(result)
    -- Process result
    local tokens = result.tokens_generated
    print("Generated " .. tokens .. " tokens")
end

return M
```

### Python Extension

```python
# my_extension.py
# RawrXD Python extension

import rawrxd_api as api

class MyExtension:
    def __init__(self):
        self.name = "PythonExtension"
        self.version = "1.0.0"
    
    def initialize(self, host):
        self.host = host
        
        # Register commands
        host.register_command("pyext.analyze", self.analyze)
        host.register_command("pyext.transform", self.transform)
        
        # Subscribe to events
        host.subscribe_event("inference_complete", self.on_inference)
        
        return True
    
    def shutdown(self):
        print("PythonExtension shutting down")
    
    def analyze(self, args):
        """Analyze code using Python libraries"""
        code = args.get("code", "")
        
        # Use Python analysis tools
        import ast
        try:
            tree = ast.parse(code)
            functions = [node.name for node in ast.walk(tree) 
                        if isinstance(node, ast.FunctionDef)]
            
            self.host.show_message(f"Found {len(functions)} functions")
        except SyntaxError as e:
            self.host.show_error(f"Syntax error: {e}")
    
    def transform(self, args):
        """Transform code"""
        code = args.get("code", "")
        
        # Apply transformations
        transformed = code.upper()  # Example transformation
        
        self.host.replace_text(args["range"], transformed)
    
    def on_inference(self, result):
        """Handle inference completion"""
        print(f"Inference completed: {result.tokens_generated} tokens")

# Export
extension = MyExtension()
```

---

## Extension API

### Core API

```cpp
// ExtensionAPI.h
#pragma once

// Version
#define RAWRXD_EXT_API_VERSION 1

// Forward declarations
class IDocument;
class IEditor;
class IInferenceEngine;

// Extension host interface
class IExtensionHost {
public:
    // Version
    virtual uint32_t GetAPIVersion() = 0;
    
    // Commands
    virtual void RegisterCommand(const char* id, 
                                  CommandHandler handler,
                                  void* user_data) = 0;
    virtual void UnregisterCommand(const char* id) = 0;
    virtual void ExecuteCommand(const char* id, 
                                 const CommandArgs* args) = 0;
    
    // Events
    virtual void SubscribeEvent(EventType type,
                                 EventHandler handler,
                                 void* user_data) = 0;
    virtual void UnsubscribeEvent(EventType type) = 0;
    
    // Documents
    virtual IDocument* GetActiveDocument() = 0;
    virtual IDocument* OpenDocument(const char* path) = 0;
    virtual void CloseDocument(IDocument* doc) = 0;
    
    // Editor
    virtual IEditor* GetEditor() = 0;
    virtual void ShowMessage(const char* message) = 0;
    virtual void ShowError(const char* message) = 0;
    
    // Inference
    virtual IInferenceEngine* GetInferenceEngine() = 0;
    virtual void SubmitInference(const InferenceRequest* request) = 0;
    
    // UI
    virtual void RegisterPanel(const char* id, 
                                  PanelFactory factory) = 0;
    virtual void ShowPanel(const char* id) = 0;
    virtual void HidePanel(const char* id) = 0;
    
    // Settings
    virtual const char* GetSetting(const char* key) = 0;
    virtual void SetSetting(const char* key, const char* value) = 0;
};

// Document interface
class IDocument {
public:
    virtual const char* GetPath() = 0;
    virtual const char* GetContent() = 0;
    virtual size_t GetLength() = 0;
    virtual void SetContent(const char* content) = 0;
    virtual void InsertText(size_t pos, const char* text) = 0;
    virtual void DeleteText(size_t start, size_t end) = 0;
    virtual void GetSelection(size_t* start, size_t* end) = 0;
    virtual void SetSelection(size_t start, size_t end) = 0;
};

// Editor interface
class IEditor {
public:
    virtual void ScrollToLine(int line) = 0;
    virtual void HighlightRange(size_t start, size_t end) = 0;
    virtual void ClearHighlights() = 0;
    virtual void ShowGhostText(size_t pos, const char* text) = 0;
    virtual void HideGhostText() = 0;
};

// Inference engine interface
class IInferenceEngine {
public:
    virtual bool IsReady() = 0;
    virtual void SetModel(const char* path) = 0;
    virtual void SetPrompt(const char* prompt) = 0;
    virtual void SetMaxTokens(int max_tokens) = 0;
    virtual void SetTemperature(float temp) = 0;
    virtual void RunAsync(InferenceCallback callback) = 0;
    virtual void Cancel() = 0;
};
```

---

## UI Extensions

### Custom Panel

```cpp
// CustomPanel.cpp
#include "ExtensionAPI.h"
#include <windows.h>

class CustomPanel {
    HWND hwnd;
    IExtensionHost* host;
    
public:
    bool Create(IExtensionHost* h, HWND parent) {
        host = h;
        
        // Register window class
        WNDCLASSEX wc = {};
        wc.cbSize = sizeof(wc);
        wc.lpfnWndProc = WindowProc;
        wc.hInstance = GetModuleHandle(nullptr);
        wc.lpszClassName = "CustomPanelClass";
        RegisterClassEx(&wc);
        
        // Create window
        hwnd = CreateWindowEx(
            0,
            "CustomPanelClass",
            "My Custom Panel",
            WS_CHILD | WS_VISIBLE,
            0, 0, 400, 300,
            parent,
            nullptr,
            GetModuleHandle(nullptr),
            this
        );
        
        // Create controls
        CreateWindow("BUTTON", "Run Analysis",
                     WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                     10, 10, 100, 30,
                     hwnd, (HMENU)1, nullptr, nullptr);
        
        CreateWindow("EDIT", "",
                     WS_CHILD | WS_VISIBLE | WS_BORDER |
                     ES_MULTILINE | ES_AUTOVSCROLL,
                     10, 50, 380, 240,
                     hwnd, nullptr, nullptr, nullptr);
        
        return true;
    }
    
    static LRESULT CALLBACK WindowProc(HWND hwnd, UINT msg,
                                      WPARAM wParam, LPARAM lParam) {
        CustomPanel* panel;
        
        if (msg == WM_CREATE) {
            panel = (CustomPanel*)((LPCREATESTRUCT)lParam)->lpCreateParams;
            SetWindowLongPtr(hwnd, GWLP_USERDATA, (LONG_PTR)panel);
        } else {
            panel = (CustomPanel*)GetWindowLongPtr(hwnd, GWLP_USERDATA);
        }
        
        switch (msg) {
            case WM_COMMAND:
                if (LOWORD(wParam) == 1) {
                    panel->OnRunAnalysis();
                }
                break;
                
            case WM_SIZE:
                // Resize controls
                break;
        }
        
        return DefWindowProc(hwnd, msg, wParam, lParam);
    }
    
    void OnRunAnalysis() {
        // Get active document
        IDocument* doc = host->GetActiveDocument();
        if (!doc) return;
        
        // Run analysis
        const char* content = doc->GetContent();
        
        // Display results
        HWND output = GetDlgItem(hwnd, 2);
        SetWindowText(output, "Analysis complete!");
    }
};
```

---

## Tool Extensions

### External Tool Integration

```cpp
// ToolExtension.cpp
class ToolExtension : public IExtension {
public:
    bool Initialize(IExtensionHost* host) override {
        // Register external tool
        host->RegisterTool("clang-format", 
                          "C:\\tools\\clang-format.exe",
                          &ToolExtension::RunClangFormat, this);
        
        host->RegisterTool("custom-linter",
                          "C:\\tools\\linter.exe",
                          &ToolExtension::RunLinter, this);
        
        return true;
    }
    
    void RunClangFormat(const char* document_path) {
        // Build command
        char cmd[512];
        snprintf(cmd, sizeof(cmd),
                 "clang-format -i \"%s\"", document_path);
        
        // Execute
        SECURITY_ATTRIBUTES sa = {};
        sa.nLength = sizeof(sa);
        sa.bInheritHandle = TRUE;
        
        HANDLE stdout_read, stdout_write;
        CreatePipe(&stdout_read, &stdout_write, &sa, 0);
        
        STARTUPINFO si = {};
        si.cb = sizeof(si);
        si.hStdOutput = stdout_write;
        si.hStdError = stdout_write;
        si.dwFlags = STARTF_USESTDHANDLES;
        
        PROCESS_INFORMATION pi = {};
        CreateProcess(nullptr, cmd, nullptr, nullptr, TRUE,
                     0, nullptr, nullptr, &si, &pi);
        
        // Read output
        char buffer[4096];
        DWORD read;
        ReadFile(stdout_read, buffer, sizeof(buffer), &read, nullptr);
        buffer[read] = '\0';
        
        // Cleanup
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        CloseHandle(stdout_read);
        CloseHandle(stdout_write);
        
        // Show results
        host->ShowMessage(buffer);
    }
    
    void RunLinter(const char* document_path) {
        // Similar implementation
    }
};
```

---

## Distribution

### Extension Package

```
MyExtension/
├── manifest.json          # Extension metadata
├── extension.dll          # Native code
├── extension.lua          # Script code (optional)
├── resources/
│   ├── icon.png
│   └── theme.css
├── docs/
│   └── README.md
└── config/
    └── default.json
```

### Manifest Format

```json
{
    "name": "MyExtension",
    "version": "1.0.0",
    "description": "A custom extension for RawrXD",
    "author": "Developer Name",
    "license": "MIT",
    
    "entry": {
        "native": "extension.dll",
        "script": "extension.lua"
    },
    
    "capabilities": [
        "document_access",
        "editor_access",
        "inference_access",
        "ui_access"
    ],
    
    "commands": [
        {
            "id": "myext.action",
            "title": "Run My Action",
            "keybinding": "Ctrl+Shift+M"
        }
    ],
    
    "events": [
        "document_open",
        "document_close",
        "inference_complete"
    ],
    
    "settings": {
        "myext.enabled": {
            "type": "boolean",
            "default": true,
            "description": "Enable extension"
        },
        "myext.timeout": {
            "type": "integer",
            "default": 30,
            "description": "Timeout in seconds"
        }
    },
    
    "dependencies": {
        "rawrxd": ">=1.0.0"
    }
}
```

### Installation

```cpp
// Extension installer
class ExtensionInstaller {
public:
    bool Install(const char* package_path) {
        // Extract package
        std::string extract_dir = GetExtensionsDir() + "/temp";
        ExtractZip(package_path, extract_dir);
        
        // Read manifest
        std::string manifest_path = extract_dir + "/manifest.json";
        json manifest = ReadJSON(manifest_path);
        
        // Validate
        if (!ValidateManifest(manifest)) {
            return false;
        }
        
        // Check dependencies
        if (!CheckDependencies(manifest["dependencies"])) {
            return false;
        }
        
        // Install
        std::string ext_name = manifest["name"];
        std::string install_dir = GetExtensionsDir() + "/" + ext_name;
        
        MoveDirectory(extract_dir, install_dir);
        
        // Register
        RegisterExtension(ext_name, manifest);
        
        return true;
    }
    
    bool Uninstall(const char* name) {
        // Unload if active
        if (IsExtensionActive(name)) {
            UnloadExtension(name);
        }
        
        // Remove directory
        std::string dir = GetExtensionsDir() + "/" + name;
        RemoveDirectory(dir);
        
        // Unregister
        UnregisterExtension(name);
        
        return true;
    }
};
```

---

## Summary

Custom extension capabilities:

- ✅ Native C++/MASM extensions
- ✅ Script extensions (Lua/Python)
- ✅ Comprehensive Extension API
- ✅ UI panel creation
- ✅ External tool integration
- ✅ Extension packaging and distribution
- ✅ Installation management

**Status:** ✅ Complete

---

*End of Custom Extensions Guide*
