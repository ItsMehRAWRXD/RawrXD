// RawrXD-Script Native Bridge
// Phase 4: IDE Integration
// Provides JavaScript access to RawrXD IDE functionality

#pragma once

#include "../masm/masm_interface.hpp"
#include <functional>
#include <map>
#include <string>
#include <vector>

namespace RawrXD {
namespace Script {
namespace Native {

// Native function signature
using NativeFunction = std::function<MASM::JsValue(
    MASM::JsValue thisArg,
    const std::vector<MASM::JsValue>& args,
    void* userData
)>;

// Native object with properties and methods
struct NativeObject {
    std::map<std::string, MASM::JsValue> properties;
    std::map<std::string, NativeFunction> methods;
};

// Native bridge - connects JS to RawrXD IDE
class NativeBridge {
public:
    NativeBridge();
    ~NativeBridge();
    
    // Initialize the bridge
    void Initialize();
    
    // Register native functions
    void RegisterFunction(const std::string& name, NativeFunction func);
    void RegisterObject(const std::string& name, const NativeObject& obj);
    
    // Call native function from JS
    MASM::JsValue CallNative(const std::string& name, 
                             MASM::JsValue thisArg,
                             const std::vector<MASM::JsValue>& args);
    
    // Get global object with all native bindings
    MASM::JsValue GetGlobalObject();
    
    // IDE-specific APIs
    void RegisterConsoleAPI();
    void RegisterWorkspaceAPI();
    void RegisterEditorAPI();
    void RegisterFileSystemAPI();
    void RegisterProcessAPI();
    void RegisterWindowAPI();
    
private:
    std::map<std::string, NativeFunction> functions_;
    std::map<std::string, NativeObject> objects_;
    MASM::JsValue globalObject_;
    bool initialized_;
    
    // Helper to convert JS values
    std::string JsValueToString(MASM::JsValue val);
    int32_t JsValueToInt(MASM::JsValue val);
    double JsValueToDouble(MASM::JsValue val);
    bool JsValueToBool(MASM::JsValue val);
    
    // Helper to create JS values
    MASM::JsValue StringToJsValue(const std::string& str);
    MASM::JsValue IntToJsValue(int32_t val);
    MASM::JsValue DoubleToJsValue(double val);
    MASM::JsValue BoolToJsValue(bool val);
};

// Global bridge instance
NativeBridge* GetNativeBridge();

} // namespace Native
} // namespace Script
} // namespace RawrXD
