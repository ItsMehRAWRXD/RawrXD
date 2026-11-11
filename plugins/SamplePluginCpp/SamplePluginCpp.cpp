// ============================================================================
// SamplePluginCpp.cpp - Example RawrXD Plugin in C++
// ============================================================================
// This is a minimal working example of a RawrXD plugin written in C++.
// It demonstrates the same functionality as the MASM version but in
// a more readable format for C++ developers.
//
// BUILD:
//   cl.exe /c /W4 /EHsc SamplePluginCpp.cpp
//   link.exe /DLL /OUT:SamplePluginCpp.dll SamplePluginCpp.obj
//
// INSTALL:
//   Copy SamplePluginCpp.dll to RawrXD/plugins/
// ============================================================================

#include <windows.h>
#include <string>
#include <string_view>
#include "../../include/RawrXD_PluginAPI.h"

// Plugin metadata
static constexpr const char* PLUGIN_NAME = "SampleCppPlugin";
static constexpr const char* PLUGIN_VERSION = "1.0.0";

// Plugin context (our state)
struct PluginContext {
    const RawrXD_API* api = nullptr;
    RawrXD_CommandHandle helloCommand = nullptr;
    RawrXD_StatusBarHandle statusPanel = nullptr;
};

// Global context instance
static PluginContext g_Context;

// Forward declarations
static int CommandHello(void* context, const char* args, char* output_buffer, size_t output_buffer_size);
static int EventHandler(void* context, const char* event_name, const char* event_data, RawrXD_DocumentHandle document);

// ============================================================================
// Plugin Entry Point (REQUIRED EXPORT)
// ============================================================================
extern "C" __declspec(dllexport) int RawrXD_PluginInitialize(
    const RawrXD_API* api,
    uint32_t api_version,
    void** plugin_context
) {
    // Check API version compatibility
    uint16_t major_version = static_cast<uint16_t>(api_version >> 16);
    if (major_version != 1) {
        // API version mismatch
        return 1; // Error code 1: version mismatch
    }
    
    // Store API pointer
    g_Context.api = api;
    
    // Log initialization
    api->Log(RAWRXD_LOG_INFO, PLUGIN_NAME, "Initializing C++ plugin...");
    
    // Register a command
    g_Context.helloCommand = api->RegisterCommand(
        "samplecpp.hello",
        "Hello from C++",
        "Ctrl+Shift+C",
        CommandHello,
        &g_Context
    );
    
    if (!g_Context.helloCommand) {
        api->Log(RAWRXD_LOG_ERROR, PLUGIN_NAME, "Failed to register command");
        return 2; // Error code 2: registration failed
    }
    
    // Create a status bar panel
    g_Context.statusPanel = api->CreateStatusBarPanel("samplecpp", 150, 1); // Right-aligned
    if (g_Context.statusPanel) {
        api->SetStatusBarText(g_Context.statusPanel, "C++ Plugin Ready");
    }
    
    // Hook events
    api->HookEvent(RAWRXD_EVENT_FILE_OPEN, EventHandler, &g_Context);
    api->HookEvent(RAWRXD_EVENT_FILE_SAVE, EventHandler, &g_Context);
    
    // Add menu item
    api->AddMenuItem("Tools", "C++ Plugin Demo", nullptr, CommandHello, &g_Context);
    
    // Show initialization message
    api->ShowMessageBox(
        "C++ Plugin",
        "Sample C++ plugin initialized successfully!\n\n"
        "Try:\n"
        "- Ctrl+Shift+C for hello command\n"
        "- Tools menu for demo\n"
        "- Open/save files to see events",
        0 // Info
    );
    
    // Return context to IDE
    *plugin_context = &g_Context;
    
    api->Log(RAWRXD_LOG_INFO, PLUGIN_NAME, "Initialization complete");
    return 0; // Success
}

// ============================================================================
// Plugin Cleanup (OPTIONAL EXPORT)
// ============================================================================
extern "C" __declspec(dllexport) int RawrXD_PluginShutdown(void* plugin_context) {
    auto* ctx = static_cast<PluginContext*>(plugin_context);
    if (!ctx || !ctx->api) {
        return 0;
    }
    
    ctx->api->Log(RAWRXD_LOG_INFO, PLUGIN_NAME, "Shutting down...");
    
    // Unregister command
    if (ctx->helloCommand) {
        ctx->api->UnregisterCommand(ctx->helloCommand);
    }
    
    // Unhook events
    ctx->api->UnhookEvent(RAWRXD_EVENT_FILE_OPEN, EventHandler);
    ctx->api->UnhookEvent(RAWRXD_EVENT_FILE_SAVE, EventHandler);
    
    ctx->api->Log(RAWRXD_LOG_INFO, PLUGIN_NAME, "Shutdown complete");
    
    return 0; // Success
}

// ============================================================================
// Command Handler
// ============================================================================
static int CommandHello(void* context, const char* args, char* output_buffer, size_t output_buffer_size) {
    auto* ctx = static_cast<PluginContext*>(context);
    if (!ctx || !ctx->api) {
        return 1;
    }
    
    // Log the command invocation
    ctx->api->Log(RAWRXD_LOG_INFO, PLUGIN_NAME, "Hello command invoked!");
    
    // Show message box
    ctx->api->ShowMessageBox(
        "C++ Plugin",
        "Hello from the C++ plugin!\n\n"
        "This demonstrates:\n"
        "- Command registration\n"
        "- Message boxes\n"
        "- Logging",
        0
    );
    
    // Update status bar
    ctx->api->SetStatusBarText(ctx->statusPanel, "Hello command executed!");
    
    // Return response
    const char* response = "Hello from C++ plugin!";
    strncpy_s(output_buffer, output_buffer_size, response, _TRUNCATE);
    
    return 0; // Success
}

// ============================================================================
// Event Handler
// ============================================================================
static int EventHandler(void* context, const char* event_name, const char* event_data, 
                        RawrXD_DocumentHandle document) {
    auto* ctx = static_cast<PluginContext*>(context);
    if (!ctx || !ctx->api) {
        return 1; // Continue processing
    }
    
    // Build log message
    char logMessage[256];
    snprintf(logMessage, sizeof(logMessage), "Event: %s", event_name);
    ctx->api->Log(RAWRXD_LOG_DEBUG, PLUGIN_NAME, logMessage);
    
    // Handle specific events
    if (strcmp(event_name, RAWRXD_EVENT_FILE_OPEN) == 0) {
        ctx->api->SetStatusBarText(ctx->statusPanel, "File opened");
        
        // Get document path if available
        if (document) {
            const char* path = ctx->api->DocumentGetPath(document);
            if (path) {
                char msg[512];
                snprintf(msg, sizeof(msg), "Opened: %s", path);
                ctx->api->Log(RAWRXD_LOG_INFO, PLUGIN_NAME, msg);
            }
        }
    }
    else if (strcmp(event_name, RAWRXD_EVENT_FILE_SAVE) == 0) {
        ctx->api->SetStatusBarText(ctx->statusPanel, "File saved");
    }
    
    return 1; // Return 1 to continue processing (don't block other handlers)
}

// ============================================================================
// DLL Entry Point (Windows requirement)
// ============================================================================
BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID lpReserved) {
    switch (reason) {
        case DLL_PROCESS_ATTACH:
            // Disable thread notifications for efficiency
            DisableThreadLibraryCalls(hModule);
            break;
            
        case DLL_PROCESS_DETACH:
            // Cleanup if needed (though RawrXD_PluginShutdown should be called first)
            break;
    }
    
    return TRUE;
}
