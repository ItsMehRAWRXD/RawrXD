// ============================================================================
// RawrXD_PluginAPI.h - Native Plugin Protocol (Stable C ABI)
// ============================================================================
// This header defines the contract between RawrXD IDE and native plugins.
// 
// DESIGN PRINCIPLES:
// - Pure C interface (no C++ name mangling, no STL)
// - Stable ABI across versions
// - MASM-compatible (no complex structs, flat function pointers)
// - Zero dependencies (Windows API only)
//
// PLUGIN LIFECYCLE:
// 1. IDE scans /plugins/*.dll on startup
// 2. IDE calls LoadLibraryW on each DLL
// 3. IDE calls GetProcAddress for "RawrXD_PluginInitialize"
// 4. IDE passes RawrXD_API struct to plugin
// 5. Plugin registers commands/hooks via function pointers
// 6. Plugin returns 0 on success, non-zero on failure
// 7. IDE calls "RawrXD_PluginShutdown" on exit (if exported)
//
// VERSIONING:
// - API_VERSION_MAJOR: Breaking changes
// - API_VERSION_MINOR: Backward-compatible additions
// ============================================================================

#ifndef RAWRXD_PLUGIN_API_H
#define RAWRXD_PLUGIN_API_H

#include <windows.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// ============================================================================
// Version Constants
// ============================================================================
#define RAWRXD_API_VERSION_MAJOR 1
#define RAWRXD_API_VERSION_MINOR 0
#define RAWRXD_API_VERSION ((RAWRXD_API_VERSION_MAJOR << 16) | RAWRXD_API_VERSION_MINOR)

// ============================================================================
// Opaque Handles (Plugin sees these as void*, IDE manages the actual objects)
// ============================================================================
typedef void* RawrXD_EditorHandle;      // Handle to editor instance
typedef void* RawrXD_DocumentHandle;    // Handle to open document
typedef void* RawrXD_CommandHandle;       // Handle to registered command
typedef void* RawrXD_MenuHandle;        // Handle to menu/menu item
typedef void* RawrXD_StatusBarHandle;     // Handle to status bar panel

// ============================================================================
// Callback Types (Function signatures for plugin exports)
// ============================================================================

// Plugin initialization - REQUIRED export
// Returns: 0 on success, non-zero error code on failure
typedef int (*RawrXD_PluginInitFunc)(
    const struct RawrXD_API_* api,     // IDE services (function pointer table)
    uint32_t api_version,                // Version of API struct
    void** plugin_context                  // OUT: Plugin stores its context here
);

// Plugin shutdown - OPTIONAL export
// Returns: 0 on success
typedef int (*RawrXD_PluginShutdownFunc)(
    void* plugin_context                 // Plugin's context from Initialize
);

// Command callback - Plugin implements this for each command
// Returns: 0 on success
typedef int (*RawrXD_CommandCallback)(
    void* plugin_context,                // Plugin's context
    const char* args,                    // Command arguments (JSON or plain text)
    char* output_buffer,                   // OUT: Response buffer (plugin writes here)
    size_t output_buffer_size              // Size of output buffer
);

// Event callback - Plugin implements this for event hooks
// Returns: 0 if event handled (IDE skips other handlers), 1 to continue
typedef int (*RawrXD_EventCallback)(
    void* plugin_context,
    const char* event_name,                // "file.open", "editor.save", etc.
    const char* event_data,                // Event data (JSON)
    RawrXD_DocumentHandle document         // Associated document (may be NULL)
);

// ============================================================================
// API Function Pointer Types (IDE implements these, plugin calls via function pointers)
// ============================================================================

// Logging
typedef void (*RawrXD_LogFunc)(
    int level,                             // 0=Debug, 1=Info, 2=Warn, 3=Error
    const char* plugin_name,               // Plugin identifier
    const char* message                    // Log message
);

// Editor Operations
typedef int (*RawrXD_EditorInsertTextFunc)(
    RawrXD_EditorHandle editor,
    const char* text,
    int64_t position                       // -1 = current cursor position
);

typedef int (*RawrXD_EditorGetTextFunc)(
    RawrXD_EditorHandle editor,
    char* buffer,
    size_t buffer_size,
    int64_t start_pos,                     // -1 = all text
    int64_t end_pos
);

typedef int (*RawrXD_EditorGetSelectionFunc)(
    RawrXD_EditorHandle editor,
    int64_t* start_pos,
    int64_t* end_pos
);

typedef int (*RawrXD_EditorSetSelectionFunc)(
    RawrXD_EditorHandle editor,
    int64_t start_pos,
    int64_t end_pos
);

// Document Operations
typedef RawrXD_DocumentHandle (*RawrXD_DocumentOpenFunc)(
    const char* file_path
);

typedef int (*RawrXD_DocumentSaveFunc)(
    RawrXD_DocumentHandle document
);

typedef const char* (*RawrXD_DocumentGetPathFunc)(
    RawrXD_DocumentHandle document
);

// Command Registration
typedef RawrXD_CommandHandle (*RawrXD_RegisterCommandFunc)(
    const char* command_id,                // Unique command identifier
    const char* display_name,              // Human-readable name
    const char* keybinding,                // e.g., "Ctrl+Shift+P" (optional, can be NULL)
    RawrXD_CommandCallback callback,       // Plugin's callback function
    void* plugin_context                   // Passed to callback
);

typedef int (*RawrXD_UnregisterCommandFunc)(
    RawrXD_CommandHandle command
);

// Event Hooks
typedef int (*RawrXD_HookEventFunc)(
    const char* event_name,                // "file.open", "file.save", "editor.change", etc.
    RawrXD_EventCallback callback,
    void* plugin_context
);

typedef int (*RawrXD_UnhookEventFunc)(
    const char* event_name,
    RawrXD_EventCallback callback
);

// UI Integration
typedef RawrXD_MenuHandle (*RawrXD_AddMenuItemFunc)(
    const char* menu_path,                 // "File", "Edit", "Tools/MyPlugin", etc.
    const char* item_name,
    const char* keybinding,
    RawrXD_CommandCallback callback,
    void* plugin_context
);

typedef int (*RawrXD_SetStatusBarTextFunc)(
    RawrXD_StatusBarHandle panel,          // NULL = default panel
    const char* text
);

typedef RawrXD_StatusBarHandle (*RawrXD_CreateStatusBarPanelFunc)(
    const char* panel_id,
    int width,
    int alignment                          // 0=Left, 1=Right
);

// Utility
typedef void (*RawrXD_GetSettingFunc)(
    const char* key,
    char* buffer,
    size_t buffer_size
);

typedef void (*RawrXD_SetSettingFunc)(
    const char* key,
    const char* value
);

typedef void (*RawrXD_ShowMessageBoxFunc)(
    const char* title,
    const char* message,
    int type                               // 0=Info, 1=Warning, 2=Error
);

typedef int (*RawrXD_ShowInputDialogFunc)(
    const char* title,
    const char* prompt,
    char* buffer,
    size_t buffer_size
);

// ============================================================================
// RawrXD_API Structure (The "OS" for plugins)
// ============================================================================
// This is the function pointer table passed to every plugin.
// Plugins call these functions to interact with the IDE.
// 
// CRITICAL ABI SAFETY RULES:
// 1. struct_size MUST be first field - never move it
// 2. New fields can only be added at the end
// 3. Never remove or reorder existing fields
// 4. Use memory management functions - never mix allocators
// 
// NOTE: Keep this struct flat and simple for MASM compatibility.
// No nested structs, no complex types, just function pointers.
// ============================================================================

typedef struct RawrXD_API_ {
    // ========================================================================
    // ABI VERSIONING (Fields 1-3) - NEVER MOVE OR REMOVE THESE
    // ========================================================================
    size_t struct_size;                    // sizeof(RawrXD_API) - for version detection
    uint32_t api_version;                  // RAWRXD_API_VERSION
    uint32_t abi_version;                  // Incremented on breaking changes
    
    // ========================================================================
    // MEMORY MANAGEMENT (Fields 4-6) - CRITICAL: Prevents heap corruption
    // ========================================================================
    // Plugins MUST use these functions for all memory operations.
    // Never use malloc/free or new/delete - different CRTs = corruption.
    // ========================================================================
    void* (*AllocateMemory)(size_t size, uint32_t flags);      // Allocate IDE-managed memory
    void (*FreeMemory)(void* ptr);                              // Free IDE-managed memory
    void* (*ReallocateMemory)(void* ptr, size_t new_size, uint32_t flags); // Resize allocation
    
    // ========================================================================
    // STRING OPERATIONS (Fields 7-9) - Safe string handling
    // ========================================================================
    char* (*StringDuplicate)(const char* str);                    // strdup using IDE allocator
    size_t (*StringLength)(const char* str);                     // strlen
    int (*StringCompare)(const char* a, const char* b, size_t max_len); // strncmp
    
    // Logging
    RawrXD_LogFunc Log;
    
    // Editor Operations
    RawrXD_EditorInsertTextFunc EditorInsertText;
    RawrXD_EditorGetTextFunc EditorGetText;
    RawrXD_EditorGetSelectionFunc EditorGetSelection;
    RawrXD_EditorSetSelectionFunc EditorSetSelection;
    
    // Document Operations
    RawrXD_DocumentOpenFunc DocumentOpen;
    RawrXD_DocumentSaveFunc DocumentSave;
    RawrXD_DocumentGetPathFunc DocumentGetPath;
    
    // Command Registration
    RawrXD_RegisterCommandFunc RegisterCommand;
    RawrXD_UnregisterCommandFunc UnregisterCommand;
    
    // Event Hooks
    RawrXD_HookEventFunc HookEvent;
    RawrXD_UnhookEventFunc UnhookEvent;
    
    // UI Integration
    RawrXD_AddMenuItemFunc AddMenuItem;
    RawrXD_SetStatusBarTextFunc SetStatusBarText;
    RawrXD_CreateStatusBarPanelFunc CreateStatusBarPanel;
    
    // Utility
    RawrXD_GetSettingFunc GetSetting;
    RawrXD_SetSettingFunc SetSetting;
    RawrXD_ShowMessageBoxFunc ShowMessageBox;
    RawrXD_ShowInputDialogFunc ShowInputDialog;
    
    // Reserved for future expansion (maintains ABI compatibility)
    void* reserved[16];
    
} RawrXD_API;

// ============================================================================
// Plugin Export Declarations
// ============================================================================
// Every plugin MUST export these functions with exact names.
// Use RAWRXD_PLUGIN_EXPORT macro for proper decoration.
//
// Example in C:
//   RAWRXD_PLUGIN_EXPORT int RawrXD_PluginInitialize(const RawrXD_API* api, ...) { ... }
//
// Example in MASM:
//   .code
//   RawrXD_PluginInitialize proc export
//       ; Plugin entry point
//       xor eax, eax  ; Return 0 for success
//       ret
//   RawrXD_PluginInitialize endp
// ============================================================================

#ifdef RAWRXD_PLUGIN_BUILD
    // Building a plugin - export functions
    #ifdef _WIN32
        #define RAWRXD_PLUGIN_EXPORT __declspec(dllexport)
    #else
        #define RAWRXD_PLUGIN_EXPORT
    #endif
#else
    // Building the IDE - import functions (not used, IDE uses GetProcAddress)
    #define RAWRXD_PLUGIN_EXPORT
#endif

// Required exports (plugin MUST implement these)
// extern "C" RAWRXD_PLUGIN_EXPORT int RawrXD_PluginInitialize(const RawrXD_API* api, uint32_t api_version, void** plugin_context);
// extern "C" RAWRXD_PLUGIN_EXPORT int RawrXD_PluginShutdown(void* plugin_context);  // Optional but recommended

// ============================================================================
// Memory Allocation Flags
// ============================================================================
#define RAWRXD_MEM_DEFAULT      0x0000  // Standard heap allocation
#define RAWRXD_MEM_ZERO_INIT    0x0001  // Zero-initialize memory
#define RAWRXD_MEM_EXECUTABLE   0x0002  // Memory can be executed (for JIT)
#define RAWRXD_MEM_LARGE_PAGES  0x0004  // Use large pages if available
#define RAWRXD_MEM_TEMPORARY    0x0008  // Short-lived allocation (hint only)

// ============================================================================
// Error Codes
// ============================================================================
typedef enum {
    RAWRXD_OK = 0,                     // Success
    RAWRXD_ERROR_GENERIC = -1,       // Generic error
    RAWRXD_ERROR_INVALID_PARAM = -2,   // Invalid parameter
    RAWRXD_ERROR_OUT_OF_MEMORY = -3,   // Memory allocation failed
    RAWRXD_ERROR_API_MISMATCH = -4,  // API version mismatch
    RAWRXD_ERROR_ABI_MISMATCH = -5,    // ABI version mismatch
    RAWRXD_ERROR_ALREADY_EXISTS = -6,  // Command/menu item already registered
    RAWRXD_ERROR_NOT_FOUND = -7,     // Resource not found
    RAWRXD_ERROR_PERMISSION_DENIED = -8, // Operation not permitted
    RAWRXD_ERROR_NOT_IMPLEMENTED = -9, // Feature not implemented
    RAWRXD_ERROR_BUSY = -10,           // Resource busy
    RAWRXD_ERROR_TIMEOUT = -11,        // Operation timed out
    RAWRXD_ERROR_EXCEPTION = -12       // Plugin caused exception
} rawrxd_error_t;

// ============================================================================
// Event Names (Standard events plugins can hook)
// ============================================================================
#define RAWRXD_EVENT_FILE_OPEN       "file.open"
#define RAWRXD_EVENT_FILE_SAVE       "file.save"
#define RAWRXD_EVENT_FILE_CLOSE      "file.close"
#define RAWRXD_EVENT_EDITOR_CHANGE   "editor.change"
#define RAWRXD_EVENT_EDITOR_SELECTION "editor.selection"
#define RAWRXD_EVENT_EDITOR_SCROLL   "editor.scroll"
#define RAWRXD_EVENT_BUILD_START     "build.start"
#define RAWRXD_EVENT_BUILD_FINISH    "build.finish"
#define RAWRXD_EVENT_DEBUG_START     "debug.start"
#define RAWRXD_EVENT_DEBUG_BREAK     "debug.break"
#define RAWRXD_EVENT_SHUTDOWN        "ide.shutdown"

// ============================================================================
// Log Levels
// ============================================================================
#define RAWRXD_LOG_DEBUG   0
#define RAWRXD_LOG_INFO    1
#define RAWRXD_LOG_WARNING 2
#define RAWRXD_LOG_ERROR   3

// ============================================================================
// Utility Macros
// ============================================================================

// Check API compatibility at runtime
#define RAWRXD_API_IS_COMPATIBLE(api_ptr, min_size) \
    ((api_ptr) != NULL && (api_ptr)->struct_size >= (min_size))

// Check version compatibility
#define RAWRXD_VERSION_IS_COMPATIBLE(provided, required) \
    ((provided) >= (required))

// Safe memory allocation with null check
#define RAWRXD_ALLOC(api, size) \
    ((api) != NULL ? (api)->AllocateMemory((size), RAWRXD_MEM_DEFAULT) : NULL)

#define RAWRXD_ALLOC_ZEROED(api, size) \
    ((api) != NULL ? (api)->AllocateMemory((size), RAWRXD_MEM_ZERO_INIT) : NULL)

// Safe memory free (sets pointer to NULL after free)
#define RAWRXD_FREE(api, ptr) \
    do { \
        if ((api) != NULL && (ptr) != NULL) { \
            (api)->FreeMemory(ptr); \
            (ptr) = NULL; \
        } \
    } while(0)

// Safe string duplication
#define RAWRXD_STRDUP(api, str) \
    ((api) != NULL && (str) != NULL ? (api)->StringDuplicate(str) : NULL)

// ============================================================================
// Exception Safety Macros (for C++ plugins)
// ============================================================================
#ifdef __cplusplus

// Wrap plugin entry points in SEH to prevent IDE crashes
#define RAWRXD_PLUGIN_ENTRY_BEGIN() \
    __try {

#define RAWRXD_PLUGIN_ENTRY_END(error_code) \
    } __except(EXCEPTION_EXECUTE_HANDLER) { \
        return (error_code); \
    }

// Wrap callback implementations
#define RAWRXD_CALLBACK_BEGIN() \
    __try {

#define RAWRXD_CALLBACK_END(default_return) \
    } __except(EXCEPTION_EXECUTE_HANDLER) { \
        return (default_return); \
    }

#else
// C plugins - no exception handling available
#define RAWRXD_PLUGIN_ENTRY_BEGIN()
#define RAWRXD_PLUGIN_ENTRY_END(error_code)
#define RAWRXD_CALLBACK_BEGIN()
#define RAWRXD_CALLBACK_END(default_return)
#endif

// ============================================================================
// C++ RAII Helpers (Optional)
// ============================================================================
#ifdef __cplusplus

namespace rawrxd {

// Smart pointer for IDE-managed memory
template<typename T>
class PluginPtr {
    const RawrXD_API_* api_;
    T* ptr_;
    
public:
    PluginPtr(const RawrXD_API_* api = nullptr, T* ptr = nullptr) 
        : api_(api), ptr_(ptr) {}
    
    ~PluginPtr() {
        if (api_ && ptr_) {
            api_->FreeMemory(ptr_);
        }
    }
    
    // Non-copyable
    PluginPtr(const PluginPtr&) = delete;
    PluginPtr& operator=(const PluginPtr&) = delete;
    
    // Movable
    PluginPtr(PluginPtr&& other) noexcept 
        : api_(other.api_), ptr_(other.ptr_) {
        other.ptr_ = nullptr;
    }
    
    PluginPtr& operator=(PluginPtr&& other) noexcept {
        if (this != &other) {
            if (api_ && ptr_) {
                api_->FreeMemory(ptr_);
            }
            api_ = other.api_;
            ptr_ = other.ptr_;
            other.ptr_ = nullptr;
        }
        return *this;
    }
    
    T* get() const { return ptr_; }
    T* operator->() const { return ptr_; }
    T& operator*() const { return *ptr_; }
    explicit operator bool() const { return ptr_ != nullptr; }
    
    T* release() {
        T* tmp = ptr_;
        ptr_ = nullptr;
        return tmp;
    }
    
    void reset(T* ptr = nullptr) {
        if (api_ && ptr_) {
            api_->FreeMemory(ptr_);
        }
        ptr_ = ptr;
    }
};

} // namespace rawrxd

#endif // __cplusplus

#ifdef __cplusplus
}
#endif

#endif // RAWRXD_PLUGIN_API_H
