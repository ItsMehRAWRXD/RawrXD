// voice_assistant_masm_bridge.cpp - C API implementation for MASM x64 integration
// Production-ready with thread safety and DEBUG conditional error handling
// ============================================================================

#include "voice_assistant_masm_bridge.hpp"
#include "voice_assistant_manager.hpp"
#include <nlohmann/json.hpp>
#include <string>
#include <memory>
#include <sstream>
#include <shared_mutex>
#include <mutex>

// ============================================================================
// Thread-local error storage with DEBUG conditional
// ============================================================================

#ifdef DEBUG
    // In DEBUG builds: store full error messages
    thread_local char g_lastError[1024] = {0};
    
    static void SetLastError(const char* msg) {
        strncpy_s(g_lastError, sizeof(g_lastError), msg, _TRUNCATE);
    }
#else
    // In RELEASE builds: store error codes only, no sensitive details
    thread_local int g_lastErrorCode = 0;
    
    static void SetLastError(const char* msg) {
        (void)msg; // Suppress unused parameter warning
        g_lastErrorCode = 1; // Generic error indicator
    }
#endif

// ============================================================================
// Thread-safe manager registry for MASM entry points
// ============================================================================

static std::shared_mutex g_manager_registry_mutex;
static std::unordered_map<void*, std::chrono::steady_clock::time_point> g_active_managers;

static void RegisterManager(void* manager) {
    std::unique_lock<std::shared_mutex> lock(g_manager_registry_mutex);
    g_active_managers[manager] = std::chrono::steady_clock::now();
}

static void UnregisterManager(void* manager) {
    std::unique_lock<std::shared_mutex> lock(g_manager_registry_mutex);
    g_active_managers.erase(manager);
}

static bool IsManagerActive(void* manager) {
    std::shared_lock<std::shared_mutex> lock(g_manager_registry_mutex);
    return g_active_managers.find(manager) != g_active_managers.end();
}

// ============================================================================
// Manager Lifecycle
// ============================================================================

VoiceAssistantManagerHandle VoiceAssistant_CreateManager(void) {
    try {
        auto* manager = new VoiceAssistantManager();
        RegisterManager(manager);
        return reinterpret_cast<VoiceAssistantManagerHandle>(manager);
    } catch (const std::exception& e) {
        SetLastError(e.what());
        return nullptr;
    }
}

void VoiceAssistant_DestroyManager(VoiceAssistantManagerHandle handle) {
    if (handle) {
        auto* manager = reinterpret_cast<VoiceAssistantManager*>(handle);
        UnregisterManager(manager);
        delete manager;
    }
}

// ============================================================================
// RAG Query API
// ============================================================================

JsonResponseHandle VoiceAssistant_QueryCodebase(
    VoiceAssistantManagerHandle handle,
    const char* query,
    const char* current_file,
    int current_line
) {
    if (!handle) {
        SetLastError("Invalid manager handle");
        return nullptr;
    }
    
    try {
        auto* manager = reinterpret_cast<VoiceAssistantManager*>(handle);
        
        std::string query_str = query ? query : "";
        std::string file_str = current_file ? current_file : "";
        
        nlohmann::json result = manager->query_codebase(query_str, file_str, current_line);
        
        // Allocate JSON string that MASM can work with
        std::string* json_str = new std::string(result.dump());
        return reinterpret_cast<JsonResponseHandle>(json_str);
        
    } catch (const std::exception& e) {
        SetLastError(e.what());
        return nullptr;
    }
}

JsonResponseHandle VoiceAssistant_ProcessVoiceInput(
    VoiceAssistantManagerHandle handle,
    const char* text,
    const char* assistant_type,
    const char* session_id
) {
    if (!handle) {
        SetLastError("Invalid manager handle");
        return nullptr;
    }
    
    try {
        auto* manager = reinterpret_cast<VoiceAssistantManager*>(handle);
        
        std::string text_str = text ? text : "";
        std::string assistant_str = assistant_type ? assistant_type : "hybrid";
        std::string session_str = session_id ? session_id : "";
        
        nlohmann::json result = manager->process_voice_input(text_str, assistant_str, session_str);
        
        std::string* json_str = new std::string(result.dump());
        return reinterpret_cast<JsonResponseHandle>(json_str);
        
    } catch (const std::exception& e) {
        SetLastError(e.what());
        return nullptr;
    }
}

// ============================================================================
// Session Management
// ============================================================================

char* VoiceAssistant_CreateSession(VoiceAssistantManagerHandle handle) {
    if (!handle) {
        SetLastError("Invalid manager handle");
        return nullptr;
    }
    
    try {
        auto* manager = reinterpret_cast<VoiceAssistantManager*>(handle);
        std::string session_id = manager->create_session();
        
        // Allocate C string for MASM
        char* result = new char[session_id.length() + 1];
        strcpy_s(result, session_id.length() + 1, session_id.c_str());
        return result;
        
    } catch (const std::exception& e) {
        SetLastError(e.what());
        return nullptr;
    }
}

void VoiceAssistant_EndSession(VoiceAssistantManagerHandle handle, const char* session_id) {
    if (!handle || !session_id) return;
    
    try {
        auto* manager = reinterpret_cast<VoiceAssistantManager*>(handle);
        manager->end_session(session_id);
    } catch (const std::exception& e) {
        SetLastError(e.what());
    }
}

// ============================================================================
// IDE Action Dispatch
// ============================================================================

JsonResponseHandle VoiceAssistant_DispatchIDEAction(
    VoiceAssistantManagerHandle handle,
    const char* intent_id
) {
    if (!handle || !intent_id) {
        SetLastError("Invalid parameters");
        return nullptr;
    }
    
    try {
        auto* manager = reinterpret_cast<VoiceAssistantManager*>(handle);
        
        // Convert string to IntentType
        IntentType intent = VoiceAssistantUtils::string_to_intent(intent_id);
        
        nlohmann::json result = manager->dispatch_ide_action(intent, {});
        
        std::string* json_str = new std::string(result.dump());
        return reinterpret_cast<JsonResponseHandle>(json_str);
        
    } catch (const std::exception& e) {
        SetLastError(e.what());
        return nullptr;
    }
}

int VoiceAssistant_HasIDEAction(VoiceAssistantManagerHandle handle, const char* intent_id) {
    if (!handle || !intent_id) return 0;
    
    try {
        auto* manager = reinterpret_cast<VoiceAssistantManager*>(handle);
        auto dispatcher = manager->get_command_dispatcher();
        
        if (!dispatcher) return 0;
        
        IntentType intent = VoiceAssistantUtils::string_to_intent(intent_id);
        return dispatcher->has_action(intent) ? 1 : 0;
        
    } catch (const std::exception& e) {
        SetLastError(e.what());
        return 0;
    }
}

// ============================================================================
// JSON Response Handling
// ============================================================================

int VoiceAssistant_JsonGetString(
    JsonResponseHandle json,
    const char* key,
    char* buffer,
    size_t buffer_size
) {
    if (!json || !key || !buffer || buffer_size == 0) return 0;
    
    try {
        std::string* json_str = reinterpret_cast<std::string*>(json);
        nlohmann::json parsed = nlohmann::json::parse(*json_str);
        
        if (!parsed.contains(key)) return 0;
        
        std::string value = parsed[key].get<std::string>();
        strncpy_s(buffer, buffer_size, value.c_str(), _TRUNCATE);
        return 1;
        
    } catch (const std::exception& e) {
        SetLastError(e.what());
        return 0;
    }
}

int VoiceAssistant_JsonGetInt(
    JsonResponseHandle json,
    const char* key,
    int* value
) {
    if (!json || !key || !value) return 0;
    
    try {
        std::string* json_str = reinterpret_cast<std::string*>(json);
        nlohmann::json parsed = nlohmann::json::parse(*json_str);
        
        if (!parsed.contains(key)) return 0;
        
        *value = parsed[key].get<int>();
        return 1;
        
    } catch (const std::exception& e) {
        SetLastError(e.what());
        return 0;
    }
}

int VoiceAssistant_JsonGetArraySize(JsonResponseHandle json, const char* key) {
    if (!json || !key) return -1;
    
    try {
        std::string* json_str = reinterpret_cast<std::string*>(json);
        nlohmann::json parsed = nlohmann::json::parse(*json_str);
        
        if (!parsed.contains(key) || !parsed[key].is_array()) return -1;
        
        return static_cast<int>(parsed[key].size());
        
    } catch (const std::exception& e) {
        SetLastError(e.what());
        return -1;
    }
}

int VoiceAssistant_JsonGetArrayString(
    JsonResponseHandle json,
    const char* key,
    int index,
    char* buffer,
    size_t buffer_size
) {
    if (!json || !key || !buffer || buffer_size == 0 || index < 0) return 0;
    
    try {
        std::string* json_str = reinterpret_cast<std::string*>(json);
        nlohmann::json parsed = nlohmann::json::parse(*json_str);
        
        if (!parsed.contains(key) || !parsed[key].is_array()) return 0;
        if (index >= static_cast<int>(parsed[key].size())) return 0;
        
        std::string value = parsed[key][index].get<std::string>();
        strncpy_s(buffer, buffer_size, value.c_str(), _TRUNCATE);
        return 1;
        
    } catch (const std::exception& e) {
        SetLastError(e.what());
        return 0;
    }
}

void VoiceAssistant_FreeJson(JsonResponseHandle json) {
    if (json) {
        std::string* json_str = reinterpret_cast<std::string*>(json);
        delete json_str;
    }
}

void VoiceAssistant_FreeString(char* str) {
    if (str) {
        delete[] str;
    }
}

// ============================================================================
// Utility Functions
// ============================================================================

void VoiceAssistant_GetLastError(char* buffer, size_t buffer_size) {
    if (!buffer || buffer_size == 0) return;
    
#ifdef DEBUG
    // In DEBUG: return full error message
    strncpy_s(buffer, buffer_size, g_lastError, _TRUNCATE);
#else
    // In RELEASE: return generic error code
    strncpy_s(buffer, buffer_size, "Error occurred (details hidden in release build)", _TRUNCATE);
#endif
        strncpy_s(buffer, buffer_size, g_lastError, _TRUNCATE);
    }
}

int VoiceAssistant_IsReady(VoiceAssistantManagerHandle handle) {
    if (!handle) return 0;
    
    try {
        auto* manager = reinterpret_cast<VoiceAssistantManager*>(handle);
        return manager->get_context_analyzer() != nullptr ? 1 : 0;
    } catch (...) {
        return 0;
    }
}

int VoiceAssistant_SetContextAnalyzer(
    VoiceAssistantManagerHandle handle,
    const char* analyzer_path
) {
    if (!handle) return 0;
    
    try {
        auto* manager = reinterpret_cast<VoiceAssistantManager*>(handle);
        
        // Create and initialize analyzer
        auto analyzer = std::make_shared<CodebaseContextAnalyzer>();
        if (analyzer_path) {
            analyzer->initialize(analyzer_path);
        }
        
        manager->set_context_analyzer(analyzer);
        return 1;
        
    } catch (const std::exception& e) {
        SetLastError(e.what());
        return 0;
    }
}
