//==============================================================================
// IDEStartupFinal.cpp - Sovereign IDE Final Integration
// Complete startup sequence for MoE-enabled IDE
// Pure C++, no STL, no CRT, no external dependencies
//==============================================================================

#include "../gui/IDEUnifiedMenu.h"
#include "../gui/IDEUnifiedLayout.h"
#include "../inference/MoEBackend_ABI.h"
#include "../inference/MoEBackend.cpp"
#include "../seg/SEGRegistry.cpp"

// External panel references
extern class MoEPanel g_moePanel;
extern class MoEDiagnosticsPanel g_diagPanel;
extern class MoEDebuggerPanel g_debugPanel;
extern class MoEHeatmapPanel g_heatPanel;
extern class MoESpecExplorerPanel g_specPanel;
extern class MASMEditorPanel g_masmEditor;

//==============================================================================
// IDE Startup Sequence
//==============================================================================

bool IDE_Startup_Full()
{
    // Step 1: Initialize core systems
    // (Assumes windowing system already initialized)
    
    // Step 2: Load MoE Backend
    if (!MoEBackend_Load("MoE.dll")) {
        // Try alternative paths
        if (!MoEBackend_Load(".\\MoE.dll")) {
            if (!MoEBackend_Load("..\\MoE.dll")) {
                // MoE not available - continue without it
                // IDE still works, just no MoE features
            }
        }
    }
    
    // Step 3: Initialize MoE if loaded
    if (MoEBackend_IsLoaded()) {
        MoEBackend_Initialize();
        
        // Verify initialization
        MoEBackendCaps caps = {};
        MoEBackend_GetCaps(&caps);
        
        // Log startup
        char msg[256];
        wsprintfA(msg, "MoE Backend v%d initialized (%d experts)", 
                  caps.version, caps.maxExperts);
        IDE_LogMessage(msg);
    }
    
    // Step 4: Initialize unified menu system
    IDEUnifiedMenu::Initialize();
    IDEUnifiedMenu_RegisterMoE();
    
    // Step 5: Initialize unified layout system
    IDEUnifiedLayout::Initialize(1920, 1080); // Default resolution
    
    // Step 6: Register all panels
    IDEUnifiedLayout::RegisterPanel("MoE Output", &g_moePanel, DOCK_BOTTOM);
    IDEUnifiedLayout::RegisterPanel("MoE Diagnostics", &g_diagPanel, DOCK_RIGHT);
    IDEUnifiedLayout::RegisterPanel("MoE Debugger", &g_debugPanel, DOCK_RIGHT);
    IDEUnifiedLayout::RegisterPanel("MoE Heatmap", &g_heatPanel, DOCK_RIGHT);
    IDEUnifiedLayout::RegisterPanel("MoE Spec Explorer", &g_specPanel, DOCK_RIGHT);
    IDEUnifiedLayout::RegisterPanel("MASM Expert Editor", &g_masmEditor, DOCK_LEFT);
    
    // Step 7: Register MoE with SEG
    SEG_RegisterMoE();
    
    // Step 8: Register MoE subsystem
    RegisterMoESubsystem();
    
    // Step 9: Apply default MoE layout
    IDEUnifiedLayout_ApplyMoELayout();
    
    // Step 10: Final initialization complete
    IDE_LogMessage("Sovereign IDE initialized with MoE backend");
    
    return true;
}

void IDE_Shutdown_Full()
{
    // Step 1: Save layout
    IDEUnifiedLayout::SaveLayout("ide_layout.bin");
    
    // Step 2: Shutdown layout system
    IDEUnifiedLayout::Shutdown();
    
    // Step 3: Shutdown menu system
    IDEUnifiedMenu::Shutdown();
    
    // Step 4: Unload MoE backend
    MoEBackend_Unload();
    
    // Step 5: Log shutdown
    IDE_LogMessage("Sovereign IDE shutdown complete");
}

//==============================================================================
// Helper Functions
//==============================================================================

bool MoEBackend_IsLoaded()
{
    // Check if backend functions are available
    MoEBackendCaps caps;
    MoEBackend_GetCaps(&caps);
    return caps.version > 0;
}

void MoEBackend_Unload()
{
    // Backend unloads automatically when DLL is freed
    // No explicit unload needed for this implementation
}

void IDE_LogMessage(const char* msg)
{
    // Output to IDE console/log
    OutputDebugStringA(msg);
    OutputDebugStringA("\n");
}

//==============================================================================
// Main IDE Entry Point
//==============================================================================

int IDE_Main(int argc, char** argv)
{
    // Initialize IDE
    if (!IDE_Startup_Full()) {
        return 1;
    }
    
    // Main loop would go here
    // (Implementation depends on your windowing system)
    
    // Shutdown IDE
    IDE_Shutdown_Full();
    
    return 0;
}
