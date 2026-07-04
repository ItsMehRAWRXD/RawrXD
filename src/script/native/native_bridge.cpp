// RawrXD-Script Native Bridge Implementation
// Phase 4: IDE Integration

#include "native_bridge.hpp"
#include <iostream>
#include <fstream>
#include <sstream>
#include <filesystem>
#include <cstdlib>

namespace fs = std::filesystem;

namespace RawrXD {
namespace Script {
namespace Native {

// Global bridge instance
static NativeBridge* g_nativeBridge = nullptr;

NativeBridge* GetNativeBridge() {
    if (!g_nativeBridge) {
        g_nativeBridge = new NativeBridge();
    }
    return g_nativeBridge;
}

NativeBridge::NativeBridge() : globalObject_(MASM::JS_NULL), initialized_(false) {}

NativeBridge::~NativeBridge() {
    // Cleanup
}

void NativeBridge::Initialize() {
    if (initialized_) return;
    
    // Register all APIs
    RegisterConsoleAPI();
    RegisterWorkspaceAPI();
    RegisterEditorAPI();
    RegisterFileSystemAPI();
    RegisterProcessAPI();
    RegisterWindowAPI();
    
    initialized_ = true;
}

void NativeBridge::RegisterFunction(const std::string& name, NativeFunction func) {
    functions_[name] = func;
}

void NativeBridge::RegisterObject(const std::string& name, const NativeObject& obj) {
    objects_[name] = obj;
}

MASM::JsValue NativeBridge::CallNative(const std::string& name,
                                        MASM::JsValue thisArg,
                                        const std::vector<MASM::JsValue>& args) {
    auto it = functions_.find(name);
    if (it != functions_.end()) {
        return it->second(thisArg, args, nullptr);
    }
    return MASM::JS_UNDEFINED;
}

// Console API
void NativeBridge::RegisterConsoleAPI() {
    NativeObject console;
    
    console.methods["log"] = [this](MASM::JsValue thisArg,
                                     const std::vector<MASM::JsValue>& args,
                                     void* userData) -> MASM::JsValue {
        for (size_t i = 0; i < args.size(); i++) {
            if (i > 0) std::cout << " ";
            std::cout << JsValueToString(args[i]);
        }
        std::cout << std::endl;
        return MASM::JS_UNDEFINED;
    };
    
    console.methods["error"] = [this](MASM::JsValue thisArg,
                                      const std::vector<MASM::JsValue>& args,
                                      void* userData) -> MASM::JsValue {
        std::cerr << "ERROR: ";
        for (size_t i = 0; i < args.size(); i++) {
            if (i > 0) std::cerr << " ";
            std::cerr << JsValueToString(args[i]);
        }
        std::cerr << std::endl;
        return MASM::JS_UNDEFINED;
    };
    
    console.methods["warn"] = [this](MASM::JsValue thisArg,
                                     const std::vector<MASM::JsValue>& args,
                                     void* userData) -> MASM::JsValue {
        std::cout << "WARNING: ";
        for (size_t i = 0; i < args.size(); i++) {
            if (i > 0) std::cout << " ";
            std::cout << JsValueToString(args[i]);
        }
        std::cout << std::endl;
        return MASM::JS_UNDEFINED;
    };
    
    console.methods["info"] = [this](MASM::JsValue thisArg,
                                     const std::vector<MASM::JsValue>& args,
                                     void* userData) -> MASM::JsValue {
        std::cout << "INFO: ";
        for (size_t i = 0; i < args.size(); i++) {
            if (i > 0) std::cout << " ";
            std::cout << JsValueToString(args[i]);
        }
        std::cout << std::endl;
        return MASM::JS_UNDEFINED;
    };
    
    console.methods["debug"] = [this](MASM::JsValue thisArg,
                                      const std::vector<MASM::JsValue>& args,
                                      void* userData) -> MASM::JsValue {
        std::cout << "DEBUG: ";
        for (size_t i = 0; i < args.size(); i++) {
            if (i > 0) std::cout << " ";
            std::cout << JsValueToString(args[i]);
        }
        std::cout << std::endl;
        return MASM::JS_UNDEFINED;
    };
    
    RegisterObject("console", console);
}

// Workspace API
void NativeBridge::RegisterWorkspaceAPI() {
    NativeObject workspace;
    
    workspace.properties["rootPath"] = StringToJsValue("d:\\rawrxd");
    
    workspace.methods["openTextDocument"] = [this](MASM::JsValue thisArg,
                                                    const std::vector<MASM::JsValue>& args,
                                                    void* userData) -> MASM::JsValue {
        if (args.empty()) return MASM::JS_NULL;
        std::string path = JsValueToString(args[0]);
        std::cout << "[Workspace] Opening document: " << path << std::endl;
        // Return document object
        return MASM::JS_NULL;
    };
    
    workspace.methods["saveAll"] = [this](MASM::JsValue thisArg,
                                            const std::vector<MASM::JsValue>& args,
                                            void* userData) -> MASM::JsValue {
        std::cout << "[Workspace] Saving all documents" << std::endl;
        return MASM::JS_UNDEFINED;
    };
    
    workspace.methods["findFiles"] = [this](MASM::JsValue thisArg,
                                             const std::vector<MASM::JsValue>& args,
                                             void* userData) -> MASM::JsValue {
        // Return array of file paths
        return MASM::JS_NULL;
    };
    
    RegisterObject("workspace", workspace);
}

// Editor API
void NativeBridge::RegisterEditorAPI() {
    NativeObject editor;
    
    editor.methods["getText"] = [this](MASM::JsValue thisArg,
                                        const std::vector<MASM::JsValue>& args,
                                        void* userData) -> MASM::JsValue {
        // Return current editor text
        return StringToJsValue("// Editor content");
    };
    
    editor.methods["setText"] = [this](MASM::JsValue thisArg,
                                        const std::vector<MASM::JsValue>& args,
                                        void* userData) -> MASM::JsValue {
        if (args.empty()) return MASM::JS_UNDEFINED;
        std::string text = JsValueToString(args[0]);
        std::cout << "[Editor] Setting text (" << text.length() << " chars)" << std::endl;
        return MASM::JS_UNDEFINED;
    };
    
    editor.methods["getSelection"] = [this](MASM::JsValue thisArg,
                                             const std::vector<MASM::JsValue>& args,
                                             void* userData) -> MASM::JsValue {
        // Return selection object {start: {line, char}, end: {line, char}}
        return MASM::JS_NULL;
    };
    
    editor.methods["insertText"] = [this](MASM::JsValue thisArg,
                                           const std::vector<MASM::JsValue>& args,
                                           void* userData) -> MASM::JsValue {
        if (args.size() < 2) return MASM::JS_UNDEFINED;
        std::string text = JsValueToString(args[0]);
        int32_t position = JsValueToInt(args[1]);
        std::cout << "[Editor] Inserting text at position " << position << std::endl;
        return MASM::JS_UNDEFINED;
    };
    
    RegisterObject("editor", editor);
}

// File System API
void NativeBridge::RegisterFileSystemAPI() {
    NativeObject fs;
    
    fs.methods["readFile"] = [this](MASM::JsValue thisArg,
                                     const std::vector<MASM::JsValue>& args,
                                     void* userData) -> MASM::JsValue {
        if (args.empty()) return StringToJsValue("");
        std::string path = JsValueToString(args[0]);
        
        std::ifstream file(path);
        if (!file) {
            return StringToJsValue("");
        }
        
        std::stringstream buffer;
        buffer << file.rdbuf();
        return StringToJsValue(buffer.str());
    };
    
    fs.methods["writeFile"] = [this](MASM::JsValue thisArg,
                                      const std::vector<MASM::JsValue>& args,
                                      void* userData) -> MASM::JsValue {
        if (args.size() < 2) return MASM::JS_UNDEFINED;
        std::string path = JsValueToString(args[0]);
        std::string content = JsValueToString(args[1]);
        
        std::ofstream file(path);
        file << content;
        
        return BoolToJsValue(file.good());
    };
    
    fs.methods["exists"] = [this](MASM::JsValue thisArg,
                                  const std::vector<MASM::JsValue>& args,
                                  void* userData) -> MASM::JsValue {
        if (args.empty()) return MASM::JS_FALSE;
        std::string path = JsValueToString(args[0]);
        return BoolToJsValue(fs::exists(path));
    };
    
    fs.methods["mkdir"] = [this](MASM::JsValue thisArg,
                                  const std::vector<MASM::JsValue>& args,
                                  void* userData) -> MASM::JsValue {
        if (args.empty()) return MASM::JS_UNDEFINED;
        std::string path = JsValueToString(args[0]);
        
        try {
            fs::create_directories(path);
            return MASM::JS_TRUE;
        } catch (...) {
            return MASM::JS_FALSE;
        }
    };
    
    fs.methods["readdir"] = [this](MASM::JsValue thisArg,
                                    const std::vector<MASM::JsValue>& args,
                                    void* userData) -> MASM::JsValue {
        // Return array of directory entries
        return MASM::JS_NULL;
    };
    
    RegisterObject("fs", fs);
}

// Process API
void NativeBridge::RegisterProcessAPI() {
    NativeObject process;
    
    process.properties["platform"] = StringToJsValue("win32");
    process.properties["arch"] = StringToJsValue("x64");
    
    process.methods["exec"] = [this](MASM::JsValue thisArg,
                                      const std::vector<MASM::JsValue>& args,
                                      void* userData) -> MASM::JsValue {
        if (args.empty()) return StringToJsValue("");
        std::string command = JsValueToString(args[0]);
        std::cout << "[Process] Executing: " << command << std::endl;
        
        // Actually execute command using system()
        int result = std::system(command.c_str());
        
        // Return result as object with stdout, stderr, exitCode
        std::string output = "Command executed with exit code: " + std::to_string(result);
        return StringToJsValue(output);
    };
    
    process.methods["exit"] = [this](MASM::JsValue thisArg,
                                      const std::vector<MASM::JsValue>& args,
                                      void* userData) -> MASM::JsValue {
        int32_t code = args.empty() ? 0 : JsValueToInt(args[0]);
        std::cout << "[Process] Exiting with code " << code << std::endl;
        exit(code);
        return MASM::JS_UNDEFINED;
    };
    
    RegisterObject("process", process);
}

// Window API
void NativeBridge::RegisterWindowAPI() {
    NativeObject window;
    
    window.methods["showInformationMessage"] = [this](MASM::JsValue thisArg,
                                                       const std::vector<MASM::JsValue>& args,
                                                       void* userData) -> MASM::JsValue {
        if (args.empty()) return MASM::JS_UNDEFINED;
        std::string message = JsValueToString(args[0]);
        std::cout << "[INFO] " << message << std::endl;
        return MASM::JS_UNDEFINED;
    };
    
    window.methods["showErrorMessage"] = [this](MASM::JsValue thisArg,
                                                 const std::vector<MASM::JsValue>& args,
                                                 void* userData) -> MASM::JsValue {
        if (args.empty()) return MASM::JS_UNDEFINED;
        std::string message = JsValueToString(args[0]);
        std::cerr << "[ERROR] " << message << std::endl;
        return MASM::JS_UNDEFINED;
    };
    
    window.methods["showInputBox"] = [this](MASM::JsValue thisArg,
                                            const std::vector<MASM::JsValue>& args,
                                            void* userData) -> MASM::JsValue {
        // Return Promise that resolves to user input
        return StringToJsValue("");
    };
    
    RegisterObject("window", window);
}

// Value conversion helpers
std::string NativeBridge::JsValueToString(MASM::JsValue val) {
    if (MASM::IsString(val)) {
        // Extract string from NaN-boxed value
        // This would need the actual string table access
        return "[string]";
    } else if (MASM::IsInt32(val)) {
        return std::to_string(MASM::UnboxInt32(val));
    } else if (val == MASM::JS_NULL) {
        return "null";
    } else if (val == MASM::JS_UNDEFINED) {
        return "undefined";
    } else if (val == MASM::JS_TRUE) {
        return "true";
    } else if (val == MASM::JS_FALSE) {
        return "false";
    }
    return "[object]";
}

int32_t NativeBridge::JsValueToInt(MASM::JsValue val) {
    if (MASM::IsInt32(val)) {
        return MASM::UnboxInt32(val);
    }
    return 0;
}

double NativeBridge::JsValueToDouble(MASM::JsValue val) {
    // Handle double values
    if (MASM::IsDouble(val)) {
        return MASM::UnboxDouble(val);
    } else if (MASM::IsInt32(val)) {
        return static_cast<double>(MASM::UnboxInt32(val));
    }
    return 0.0;
}

bool NativeBridge::JsValueToBool(MASM::JsValue val) {
    if (val == MASM::JS_FALSE || val == MASM::JS_NULL || val == MASM::JS_UNDEFINED) {
        return false;
    }
    return true;
}

MASM::JsValue NativeBridge::StringToJsValue(const std::string& str) {
    // Allocate string in arena with header
    // Layout: [Header: type+length][Data: chars...][Null terminator]
    size_t allocSize = sizeof(MASM::StringHeader) + str.length() + 1;
    void* mem = arena_->Allocate(allocSize);
    if (!mem) return MASM::JS_NULL;
    
    // Initialize header
    MASM::StringHeader* header = static_cast<MASM::StringHeader*>(mem);
    header->type = MASM::TypeTag::kString;
    header->length = static_cast<uint32_t>(str.length());
    header->hash = 0;  // Computed on first access
    
    // Copy string data
    char* data = reinterpret_cast<char*>(header + 1);
    std::memcpy(data, str.c_str(), str.length() + 1);
    
    // Return NaN-boxed pointer
    return MASM::BoxString(header);
}

MASM::JsValue NativeBridge::IntToJsValue(int32_t val) {
    return MASM::BoxInt32(val);
}

MASM::JsValue NativeBridge::DoubleToJsValue(double val) {
    // Check if double is actually an integer
    if (val == static_cast<int32_t>(val) && 
        val >= INT32_MIN && val <= INT32_MAX) {
        // Use int32 representation for integers
        return MASM::BoxInt32(static_cast<int32_t>(val));
    }
    
    // Box as double
    return MASM::BoxDouble(val);
}

MASM::JsValue NativeBridge::BoolToJsValue(bool val) {
    return val ? MASM::JS_TRUE : MASM::JS_FALSE;
}

} // namespace Native
} // namespace Script
} // namespace RawrXD
