// voice_assistant_masm_bridge.hpp - C-compatible bridge for MASM x64 integration
// Exports C functions that MASM can call via GetProcAddress or direct linking
// ============================================================================

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

// ============================================================================
// Opaque Handles (MASM-friendly void* pointers)
// ============================================================================

typedef void* VoiceAssistantManagerHandle;
typedef void* SessionHandle;
typedef void* JsonResponseHandle;

// ============================================================================
// Manager Lifecycle (C API for MASM)
// ============================================================================

// Create a new VoiceAssistantManager instance
// Returns: Handle to manager or NULL on failure
VoiceAssistantManagerHandle VoiceAssistant_CreateManager(void);

// Destroy manager and free resources
// Parameters: handle - Manager instance to destroy
void VoiceAssistant_DestroyManager(VoiceAssistantManagerHandle handle);

// ============================================================================
// RAG Query API (C API for MASM)
// ============================================================================

// Execute a semantic code query
// Parameters:
//   manager - VoiceAssistantManager instance
//   query - Natural language query string (UTF-8)
//   current_file - Current file path (can be NULL)
//   current_line - Current line number
// Returns: JSON response handle (must be freed with VoiceAssistant_FreeJson)
JsonResponseHandle VoiceAssistant_QueryCodebase(
    VoiceAssistantManagerHandle manager,
    const char* query,
    const char* current_file,
    int current_line
);

// Process voice input
// Parameters:
//   manager - VoiceAssistantManager instance
//   text - Voice input text (UTF-8)
//   assistant_type - "siri", "alexa", or "hybrid"
//   session_id - Session ID (can be NULL for auto-create)
// Returns: JSON response handle
JsonResponseHandle VoiceAssistant_ProcessVoiceInput(
    VoiceAssistantManagerHandle manager,
    const char* text,
    const char* assistant_type,
    const char* session_id
);

// ============================================================================
// Session Management (C API for MASM)
// ============================================================================

// Create a new session
// Parameters: manager - VoiceAssistantManager instance
// Returns: Session ID string (must be freed with VoiceAssistant_FreeString)
char* VoiceAssistant_CreateSession(VoiceAssistantManagerHandle manager);

// End a session
// Parameters:
//   manager - VoiceAssistantManager instance
//   session_id - Session ID to end
void VoiceAssistant_EndSession(VoiceAssistantManagerHandle manager, const char* session_id);

// ============================================================================
// IDE Action Dispatch (C API for MASM)
// ============================================================================

// Dispatch an IDE action by intent ID
// Parameters:
//   manager - VoiceAssistantManager instance
//   intent_id - Intent string (e.g., "ide_build", "ide_run")
// Returns: JSON response handle
JsonResponseHandle VoiceAssistant_DispatchIDEAction(
    VoiceAssistantManagerHandle manager,
    const char* intent_id
);

// Check if an IDE action is available
// Parameters:
//   manager - VoiceAssistantManager instance
//   intent_id - Intent string to check
// Returns: 1 if available, 0 if not
int VoiceAssistant_HasIDEAction(VoiceAssistantManagerHandle manager, const char* intent_id);

// ============================================================================
// JSON Response Handling (C API for MASM)
// ============================================================================

// Get string value from JSON by key
// Parameters:
//   json - JSON response handle
//   key - Key to look up
//   buffer - Output buffer
//   buffer_size - Size of output buffer
// Returns: 1 if found, 0 if not found
int VoiceAssistant_JsonGetString(
    JsonResponseHandle json,
    const char* key,
    char* buffer,
    size_t buffer_size
);

// Get integer value from JSON by key
// Parameters:
//   json - JSON response handle
//   key - Key to look up
//   value - Output value pointer
// Returns: 1 if found, 0 if not found
int VoiceAssistant_JsonGetInt(
    JsonResponseHandle json,
    const char* key,
    int* value
);

// Get array size from JSON by key
// Parameters:
//   json - JSON response handle
//   key - Array key to look up
// Returns: Array size, or -1 if not found/not an array
int VoiceAssistant_JsonGetArraySize(JsonResponseHandle json, const char* key);

// Get string from JSON array
// Parameters:
//   json - JSON response handle
//   key - Array key
//   index - Array index
//   buffer - Output buffer
//   buffer_size - Size of output buffer
// Returns: 1 if found, 0 if not found
int VoiceAssistant_JsonGetArrayString(
    JsonResponseHandle json,
    const char* key,
    int index,
    char* buffer,
    size_t buffer_size
);

// Free JSON response
// Parameters: json - JSON response handle to free
void VoiceAssistant_FreeJson(JsonResponseHandle json);

// Free string returned by API
// Parameters: str - String to free
void VoiceAssistant_FreeString(char* str);

// ============================================================================
// Utility Functions (C API for MASM)
// ============================================================================

// Get last error message
// Parameters:
//   buffer - Output buffer
//   buffer_size - Size of output buffer
void VoiceAssistant_GetLastError(char* buffer, size_t buffer_size);

// Check if manager is ready for queries
// Parameters: manager - VoiceAssistantManager instance
// Returns: 1 if ready, 0 if not
int VoiceAssistant_IsReady(VoiceAssistantManagerHandle manager);

// Set context analyzer (for dependency injection)
// Parameters:
//   manager - VoiceAssistantManager instance
//   analyzer_path - Path to codebase for analysis
// Returns: 1 on success, 0 on failure
int VoiceAssistant_SetContextAnalyzer(
    VoiceAssistantManagerHandle manager,
    const char* analyzer_path
);

#ifdef __cplusplus
}
#endif
