//==============================================================================
// SovereignSelfBuildLoop.h - Self-Building Runtime Integration Layer
// Connects Artifact Scanner → Manifestor → Generators → Build → Reload → IDE
// Pure C++, no STL, no CRT, no external dependencies
//==============================================================================

#ifndef SOVEREIGN_SELF_BUILD_LOOP_H
#define SOVEREIGN_SELF_BUILD_LOOP_H

#include "ArtifactScanner.h"

//==============================================================================
// Self-Build Configuration
//==============================================================================

struct SelfBuildConfig {
    bool enableAutoManifest;      // Update manifest automatically
    bool enableAutoGenerate;      // Run generators automatically
    bool enableAutoBuild;         // Build automatically
    bool enableAutoReload;        // Reload runtime automatically
    bool enableAutoRefreshIDE;    // Refresh IDE automatically
    bool enableDaemonMode;        // Run continuously in background
    unsigned int scanIntervalMs;  // Daemon scan interval
};

// Default configuration
static const SelfBuildConfig SELF_BUILD_CONFIG_DEFAULT = {
    true,   // enableAutoManifest
    true,   // enableAutoGenerate
    true,   // enableAutoBuild
    true,   // enableAutoReload
    true,   // enableAutoRefreshIDE
    false,  // enableDaemonMode
    1000    // scanIntervalMs
};

//==============================================================================
// Self-Build Loop Interface
//==============================================================================

// Main entry point - runs one iteration of the self-build loop
void SovereignSelfBuildLoop_Run(const SelfBuildConfig& cfg);

// Convenience wrapper with default config
void SovereignSelfBuildLoop_RunDefault();

// Check if self-build is needed (dry run)
bool SovereignSelfBuildLoop_NeedsBuild();

// Get last build status
struct BuildStatus {
    bool manifestUpdated;
    bool generated;
    bool builtAsm;
    bool builtCpp;
    bool reloadedMoE;
    bool reloadedSubsystems;
    bool refreshedIDE;
    unsigned int timestamp;
};

void SovereignSelfBuildLoop_GetStatus(BuildStatus* status);

//==============================================================================
// External Component Interfaces (forward declarations)
//==============================================================================

// Manifestor
void SovereignManifestor_Run();
bool SovereignManifestor_NeedsUpdate();

// Generators
void SovereignGenerators_Run();
void SovereignGenerators_RunFor(const char* artifactType, const char* artifactName);

// Build Orchestrator
void SovereignBuild_Run(bool rebuildAsm, bool rebuildCpp);
void SovereignBuild_Clean();
bool SovereignBuild_IsBuilding();

// Reload Managers
void SovereignReload_MoE();
void SovereignReload_Subsystems();
void SovereignReload_Workflows();
void SovereignReload_SEG();
void SovereignReload_All();

// IDE Refresh
void IDE_RefreshAll();
void IDE_RefreshPanel(const char* panelName);
void IDE_RefreshSubsystemInspector();

//==============================================================================
// Daemon Mode
//==============================================================================

// Start/stop background daemon
void SovereignAutoBuildDaemon_Start(const SelfBuildConfig& cfg);
void SovereignAutoBuildDaemon_Stop();
bool SovereignAutoBuildDaemon_IsRunning();

// Trigger manual daemon tick (for testing)
void SovereignAutoBuildDaemon_Tick();

//==============================================================================
// Event Hooks
//==============================================================================

typedef void (*SelfBuildCallback)(const BuildStatus* status, void* userData);

void SovereignSelfBuildLoop_SetCallback(SelfBuildCallback callback, void* userData);
void SovereignSelfBuildLoop_ClearCallback();

//==============================================================================
// Integration Helpers
//==============================================================================

// Call this from IDE startup
void SovereignSelfBuildLoop_Initialize();

// Call this from IDE shutdown
void SovereignSelfBuildLoop_Shutdown();

// Call this when files change (from file watcher)
void SovereignSelfBuildLoop_OnFileChanged(const char* path);

// Call this when manifest changes
void SovereignSelfBuildLoop_OnManifestChanged();

// Call this when build completes (from build orchestrator)
void SovereignSelfBuildLoop_OnBuildComplete(bool success);

#endif // SOVEREIGN_SELF_BUILD_LOOP_H
