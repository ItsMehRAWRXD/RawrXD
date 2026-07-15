//==============================================================================
// SovereignSelfBuildLoop.cpp - Self-Building Runtime Integration Implementation
// Connects Artifact Scanner → Manifestor → Generators → Build → Reload → IDE
// Pure C++, no STL, no CRT, no external dependencies
//==============================================================================

#include "SovereignSelfBuildLoop.h"
#include <windows.h>

//==============================================================================
// Static State
//==============================================================================

static bool s_initialized = false;
static BuildStatus s_lastStatus = {0};
static SelfBuildCallback s_callback = nullptr;
static void* s_callbackUserData = nullptr;
static bool s_buildInProgress = false;

//==============================================================================
// Main Self-Build Loop
//==============================================================================

void SovereignSelfBuildLoop_Run(const SelfBuildConfig& cfg)
{
    if (!s_initialized) {
        SovereignSelfBuildLoop_Initialize();
    }
    
    if (s_buildInProgress) {
        // Skip if build already in progress
        return;
    }
    
    s_buildInProgress = true;
    
    // Clear status
    memset(&s_lastStatus, 0, sizeof(s_lastStatus));
    s_lastStatus.timestamp = GetTickCount();
    
    // Step 1: Artifact Scan
    ScanResults scan;
    ArtifactScanner::ScanAll(&scan);
    
    // Determine what needs to be done
    bool needManifest = cfg.enableAutoManifest && 
                        (scan.missingCount > 0 || 
                         scan.undeclaredCount > 0 || 
                         scan.mismatchedCount > 0);
    
    bool needGenerate = cfg.enableAutoGenerate && 
                        (scan.missingCount > 0 || 
                         scan.mismatchedCount > 0);
    
    bool needBuildAsm = cfg.enableAutoBuild && 
                        (scan.outdatedCount > 0 || 
                         scan.missingCount > 0);
    
    bool needBuildCpp = cfg.enableAutoBuild && 
                        (scan.outdatedCount > 0);
    
    bool needReload = cfg.enableAutoReload && 
                      (needBuildAsm || needBuildCpp || needGenerate || needManifest);
    
    // Step 2: Manifest Update
    if (needManifest) {
        OutputDebugStringA("[SelfBuild] Updating manifest...\n");
        SovereignManifestor_Run();
        s_lastStatus.manifestUpdated = true;
        
        // Re-scan after manifest update
        ArtifactScanner::ScanAll(&scan);
    }
    
    // Step 3: Generator Update
    if (needGenerate) {
        OutputDebugStringA("[SelfBuild] Running generators...\n");
        SovereignGenerators_Run();
        s_lastStatus.generated = true;
        
        // Generate missing artifacts specifically
        for (unsigned int i = 0; i < scan.count; i++) {
            if (scan.entries[i].status == STATUS_MISSING) {
                const char* typeStr = "";
                switch (scan.entries[i].type) {
                    case ARTIFACT_SUBSYSTEM: typeStr = "subsystem"; break;
                    case ARTIFACT_EXPERT: typeStr = "expert"; break;
                    case ARTIFACT_WORKFLOW: typeStr = "workflow"; break;
                    case ARTIFACT_SEG_NODE: typeStr = "seg"; break;
                    case ARTIFACT_VSCODE_COMMAND: typeStr = "vscode"; break;
                    case ARTIFACT_HTTP_ROUTE: typeStr = "http"; break;
                    default: break;
                }
                
                if (typeStr[0]) {
                    SovereignGenerators_RunFor(typeStr, scan.entries[i].name);
                }
            }
        }
    }
    
    // Step 4: Build
    if (needBuildAsm || needBuildCpp) {
        OutputDebugStringA("[SelfBuild] Building...\n");
        SovereignBuild_Run(needBuildAsm, needBuildCpp);
        s_lastStatus.builtAsm = needBuildAsm;
        s_lastStatus.builtCpp = needBuildCpp;
    }
    
    // Step 5: Reload Runtime
    if (needReload) {
        OutputDebugStringA("[SelfBuild] Reloading runtime...\n");
        
        if (needBuildAsm) {
            SovereignReload_MoE();
            s_lastStatus.reloadedMoE = true;
        }
        
        if (needBuildCpp) {
            SovereignReload_Subsystems();
            s_lastStatus.reloadedSubsystems = true;
        }
        
        if (needGenerate || needManifest) {
            SovereignReload_Workflows();
            SovereignReload_SEG();
        }
    }
    
    // Step 6: Refresh IDE
    if (cfg.enableAutoRefreshIDE && needReload) {
        OutputDebugStringA("[SelfBuild] Refreshing IDE...\n");
        IDE_RefreshAll();
        s_lastStatus.refreshedIDE = true;
    }
    
    // Report to callback
    if (s_callback) {
        s_callback(&s_lastStatus, s_callbackUserData);
    }
    
    // Report to IDE
    ArtifactScanner::ReportToIDE(&scan);
    
    s_buildInProgress = false;
    
    // Log completion
    char msg[256];
    wsprintfA(msg, "[SelfBuild] Complete. Manifest:%d Gen:%d BuildAsm:%d BuildCpp:%d Reload:%d\n",
              s_lastStatus.manifestUpdated,
              s_lastStatus.generated,
              s_lastStatus.builtAsm,
              s_lastStatus.builtCpp,
              needReload);
    OutputDebugStringA(msg);
}

void SovereignSelfBuildLoop_RunDefault()
{
    SovereignSelfBuildLoop_Run(SELF_BUILD_CONFIG_DEFAULT);
}

bool SovereignSelfBuildLoop_NeedsBuild()
{
    ScanResults scan;
    ArtifactScanner::ScanAll(&scan);
    
    return (scan.missingCount > 0 ||
            scan.outdatedCount > 0 ||
            scan.mismatchedCount > 0 ||
            scan.undeclaredCount > 0);
}

void SovereignSelfBuildLoop_GetStatus(BuildStatus* status)
{
    if (status) {
        *status = s_lastStatus;
    }
}

//==============================================================================
// Initialization / Shutdown
//==============================================================================

void SovereignSelfBuildLoop_Initialize()
{
    if (s_initialized) return;
    
    ArtifactScanner::Initialize();
    
    s_initialized = true;
    
    OutputDebugStringA("[SelfBuild] Initialized\n");
}

void SovereignSelfBuildLoop_Shutdown()
{
    if (!s_initialized) return;
    
    ArtifactScanner::Shutdown();
    
    s_initialized = false;
    s_callback = nullptr;
    s_callbackUserData = nullptr;
    
    OutputDebugStringA("[SelfBuild] Shutdown\n");
}

//==============================================================================
// Event Hooks
//==============================================================================

void SovereignSelfBuildLoop_OnFileChanged(const char* path)
{
    if (!path) return;
    
    char msg[512];
    wsprintfA(msg, "[SelfBuild] File changed: %s\n", path);
    OutputDebugStringA(msg);
    
    // Trigger self-build
    SovereignSelfBuildLoop_RunDefault();
}

void SovereignSelfBuildLoop_OnManifestChanged()
{
    OutputDebugStringA("[SelfBuild] Manifest changed\n");
    
    // Trigger self-build with manifest update
    SelfBuildConfig cfg = SELF_BUILD_CONFIG_DEFAULT;
    cfg.enableAutoManifest = true;
    SovereignSelfBuildLoop_Run(cfg);
}

void SovereignSelfBuildLoop_OnBuildComplete(bool success)
{
    if (success) {
        OutputDebugStringA("[SelfBuild] Build completed successfully\n");
        
        // Trigger reload
        SovereignReload_All();
        IDE_RefreshAll();
    } else {
        OutputDebugStringA("[SelfBuild] Build failed\n");
    }
}

//==============================================================================
// Callback Management
//==============================================================================

void SovereignSelfBuildLoop_SetCallback(SelfBuildCallback callback, void* userData)
{
    s_callback = callback;
    s_callbackUserData = userData;
}

void SovereignSelfBuildLoop_ClearCallback()
{
    s_callback = nullptr;
    s_callbackUserData = nullptr;
}

//==============================================================================
// Daemon Mode Implementation
//==============================================================================

static HANDLE s_daemonThread = nullptr;
static volatile bool s_daemonRunning = false;
static SelfBuildConfig s_daemonConfig = {0};

static DWORD WINAPI DaemonThreadProc(LPVOID)
{
    OutputDebugStringA("[SelfBuildDaemon] Started\n");
    
    while (s_daemonRunning) {
        // Run self-build loop
        SovereignSelfBuildLoop_Run(s_daemonConfig);
        
        // Sleep for interval
        Sleep(s_daemonConfig.scanIntervalMs);
    }
    
    OutputDebugStringA("[SelfBuildDaemon] Stopped\n");
    return 0;
}

void SovereignAutoBuildDaemon_Start(const SelfBuildConfig& cfg)
{
    if (s_daemonRunning) return;
    
    s_daemonConfig = cfg;
    s_daemonRunning = true;
    
    s_daemonThread = CreateThread(
        nullptr,           // default security
        0,                 // default stack size
        DaemonThreadProc,  // thread function
        nullptr,           // thread parameter
        0,                 // creation flags
        nullptr            // thread ID
    );
    
    if (s_daemonThread) {
        char msg[256];
        wsprintfA(msg, "[SelfBuildDaemon] Started with interval %dms\n", cfg.scanIntervalMs);
        OutputDebugStringA(msg);
    }
}

void SovereignAutoBuildDaemon_Stop()
{
    if (!s_daemonRunning) return;
    
    s_daemonRunning = false;
    
    if (s_daemonThread) {
        WaitForSingleObject(s_daemonThread, INFINITE);
        CloseHandle(s_daemonThread);
        s_daemonThread = nullptr;
    }
    
    OutputDebugStringA("[SelfBuildDaemon] Stopped\n");
}

bool SovereignAutoBuildDaemon_IsRunning()
{
    return s_daemonRunning;
}

void SovereignAutoBuildDaemon_Tick()
{
    // Manual tick for testing
    if (s_initialized) {
        SovereignSelfBuildLoop_Run(s_daemonConfig);
    }
}

//==============================================================================
// Stub Implementations (to be provided by actual components)
//==============================================================================

// These are stubs that should be replaced with actual implementations
// from your Manifestor, Generators, Build Orchestrator, etc.

void SovereignManifestor_Run()
{
    OutputDebugStringA("[Manifestor] Running...\n");
    // TODO: Call actual manifestor
}

bool SovereignManifestor_NeedsUpdate()
{
    // TODO: Check if manifest needs update
    return false;
}

void SovereignGenerators_Run()
{
    OutputDebugStringA("[Generators] Running...\n");
    // TODO: Call actual generators
}

void SovereignGenerators_RunFor(const char* artifactType, const char* artifactName)
{
    char msg[512];
    wsprintfA(msg, "[Generators] Running for %s: %s\n", artifactType, artifactName);
    OutputDebugStringA(msg);
    // TODO: Call specific generator
}

void SovereignBuild_Run(bool rebuildAsm, bool rebuildCpp)
{
    char msg[256];
    wsprintfA(msg, "[Build] Running (ASM:%d CPP:%d)...\n", rebuildAsm, rebuildCpp);
    OutputDebugStringA(msg);
    
    if (rebuildAsm) {
        // Build MASM
        STARTUPINFOA si = { sizeof(si) };
        PROCESS_INFORMATION pi;
        CreateProcessA(nullptr, (LPSTR)"build_moe_dll.bat", nullptr, nullptr, 
                       FALSE, 0, nullptr, nullptr, &si, &pi);
        WaitForSingleObject(pi.hProcess, INFINITE);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
    
    if (rebuildCpp) {
        // Build C++
        STARTUPINFOA si = { sizeof(si) };
        PROCESS_INFORMATION pi;
        CreateProcessA(nullptr, (LPSTR)"build_ide.bat", nullptr, nullptr,
                       FALSE, 0, nullptr, nullptr, &si, &pi);
        WaitForSingleObject(pi.hProcess, INFINITE);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
}

void SovereignBuild_Clean()
{
    OutputDebugStringA("[Build] Cleaning...\n");
    // TODO: Clean build artifacts
}

bool SovereignBuild_IsBuilding()
{
    return s_buildInProgress;
}

void SovereignReload_MoE()
{
    OutputDebugStringA("[Reload] Reloading MoE...\n");
    // TODO: Reload MoE.dll and patch jump table
}

void SovereignReload_Subsystems()
{
    OutputDebugStringA("[Reload] Reloading subsystems...\n");
    // TODO: Re-register subsystems
}

void SovereignReload_Workflows()
{
    OutputDebugStringA("[Reload] Reloading workflows...\n");
    // TODO: Reload workflow templates
}

void SovereignReload_SEG()
{
    OutputDebugStringA("[Reload] Reloading SEG...\n");
    // TODO: Reload SEG nodes
}

void SovereignReload_All()
{
    SovereignReload_MoE();
    SovereignReload_Subsystems();
    SovereignReload_Workflows();
    SovereignReload_SEG();
}

void IDE_RefreshAll()
{
    OutputDebugStringA("[IDE] Refreshing all panels...\n");
    // TODO: Refresh all IDE panels
}

void IDE_RefreshPanel(const char* panelName)
{
    char msg[256];
    wsprintfA(msg, "[IDE] Refreshing panel: %s\n", panelName);
    OutputDebugStringA(msg);
    // TODO: Refresh specific panel
}

void IDE_RefreshSubsystemInspector()
{
    OutputDebugStringA("[IDE] Refreshing subsystem inspector...\n");
    // TODO: Refresh subsystem inspector
}
