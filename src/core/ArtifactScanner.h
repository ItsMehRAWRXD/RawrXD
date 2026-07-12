//==============================================================================
// ArtifactScanner.h - Sovereign Runtime Artifact Detection System
// Detects: existing, missing, outdated, undeclared, mismatched artifacts
// Pure C++, no STL, no CRT, no external dependencies
//==============================================================================

#ifndef ARTIFACT_SCANNER_H
#define ARTIFACT_SCANNER_H

#include <windows.h>

// Artifact types
enum ArtifactType {
    ARTIFACT_SUBSYSTEM,
    ARTIFACT_EXPERT,
    ARTIFACT_WORKFLOW,
    ARTIFACT_SEG_NODE,
    ARTIFACT_VSCODE_COMMAND,
    ARTIFACT_HTTP_ROUTE,
    ARTIFACT_MASM_STUB,
    ARTIFACT_WRAPPER,
    ARTIFACT_COUNT
};

// Artifact status
enum ArtifactStatus {
    STATUS_OK,              // Declared, present, up-to-date
    STATUS_MISSING,         // Declared in manifest, not on disk
    STATUS_UNDECLARED,      // Present on disk, not in manifest
    STATUS_OUTDATED,        // Present but older than source
    STATUS_MISMATCHED,      // Caps/type mismatch
    STATUS_UNREGISTERED,    // Present but not in runtime registry
    STATUS_ERROR
};

// Artifact entry
struct ArtifactEntry {
    char name[128];
    char path[256];
    ArtifactType type;
    ArtifactStatus status;
    FILETIME sourceTime;    // .asm, .cpp, .toml timestamp
    FILETIME binaryTime;    // .dll, .obj timestamp
    char expectedCaps[256];
    char actualCaps[256];
    char message[512];
    bool registered;
};

// Scan results
struct ScanResults {
    ArtifactEntry entries[256];
    unsigned int count;
    unsigned int okCount;
    unsigned int missingCount;
    unsigned int undeclaredCount;
    unsigned int outdatedCount;
    unsigned int mismatchedCount;
    unsigned int unregisteredCount;
};

// Artifact Scanner class
class ArtifactScanner {
public:
    static void Initialize();
    static void Shutdown();
    
    // Full scan
    static void ScanAll(ScanResults* results);
    
    // Individual scans
    static void ScanManifest(ScanResults* results);
    static void ScanFilesystem(ScanResults* results);
    static void ScanRegistry(ScanResults* results);
    static void CheckTimestamps(ScanResults* results);
    static void CheckCapabilities(ScanResults* results);
    
    // Specific artifact checks
    static bool CheckSubsystem(const char* name);
    static bool CheckExpert(const char* language, const char* name);
    static bool CheckWorkflow(const char* name);
    static bool CheckSEGNode(const char* name);
    
    // Auto-fix operations
    static void GenerateMissing(ScanResults* results);
    static void UpdateOutdated(ScanResults* results);
    static void RegisterUnregistered(ScanResults* results);
    
    // Reporting
    static void ReportToIDE(const ScanResults* results);
    static void ExportReport(const char* path, const ScanResults* results);
    
private:
    static bool s_initialized;
    static char s_manifestPath[MAX_PATH];
    
    static void ParseManifestEntry(const char* line, const char* section, 
                                   ScanResults* results);
    static void ScanDirectory(const char* dir, const char* pattern, 
                              ArtifactType type, ScanResults* results);
    static void CompareEntry(ArtifactEntry* entry);
    static ArtifactStatus DetermineStatus(const ArtifactEntry* entry);
    static void FormatMessage(ArtifactEntry* entry);
    
    static bool FileExists(const char* path);
    static bool GetFileTime(const char* path, FILETIME* ft);
    static bool IsOlder(const FILETIME* a, const FILETIME* b);
    static void AddEntry(ScanResults* results, const ArtifactEntry* entry);
};

// IDE integration
void ArtifactScanner_InitializePanel();
void ArtifactScanner_RefreshPanel();
void ArtifactScanner_DrawPanel();

// Hotpatch integration
void ArtifactScanner_TriggerHotpatch(const char* artifactName);
bool ArtifactScanner_CanHotpatch(const char* artifactName);

#endif // ARTIFACT_SCANNER_H
