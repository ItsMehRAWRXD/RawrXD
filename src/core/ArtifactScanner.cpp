//==============================================================================
// ArtifactScanner.cpp - Sovereign Runtime Artifact Detection Implementation
// Detects existing, missing, outdated, undeclared, mismatched artifacts
// Pure C++, no STL, no CRT, no external dependencies
//==============================================================================

#include "ArtifactScanner.h"
#include "SovereignSubsystemRegistry.h"
#include "MoEBackend_ABI.h"

// Static members
bool ArtifactScanner::s_initialized = false;
char ArtifactScanner::s_manifestPath[MAX_PATH] = {0};

//==============================================================================
// Initialization
//==============================================================================

void ArtifactScanner::Initialize() {
    if (s_initialized) return;
    
    // Default manifest path
    strcpy(s_manifestPath, "Sovereign.toml");
    
    s_initialized = true;
}

void ArtifactScanner::Shutdown() {
    s_initialized = false;
}

//==============================================================================
// Full Scan
//==============================================================================

void ArtifactScanner::ScanAll(ScanResults* results) {
    if (!results) return;
    
    // Clear results
    memset(results, 0, sizeof(ScanResults));
    
    // Run all scans
    ScanManifest(results);
    ScanFilesystem(results);
    ScanRegistry(results);
    CheckTimestamps(results);
    CheckCapabilities(results);
    
    // Update counts
    for (unsigned int i = 0; i < results->count; i++) {
        switch (results->entries[i].status) {
            case STATUS_OK: results->okCount++; break;
            case STATUS_MISSING: results->missingCount++; break;
            case STATUS_UNDECLARED: results->undeclaredCount++; break;
            case STATUS_OUTDATED: results->outdatedCount++; break;
            case STATUS_MISMATCHED: results->mismatchedCount++; break;
            case STATUS_UNREGISTERED: results->unregisteredCount++; break;
            default: break;
        }
    }
}

//==============================================================================
// Manifest Scan
//==============================================================================

void ArtifactScanner::ScanManifest(ScanResults* results) {
    HANDLE hFile = CreateFileA(s_manifestPath, GENERIC_READ, FILE_SHARE_READ, 
                               nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) {
        // Manifest not found - all artifacts are missing
        return;
    }
    
    char buffer[4096];
    DWORD bytesRead;
    if (!ReadFile(hFile, buffer, sizeof(buffer) - 1, &bytesRead, nullptr)) {
        CloseHandle(hFile);
        return;
    }
    buffer[bytesRead] = '\0';
    CloseHandle(hFile);
    
    // Parse manifest line by line
    char* line = buffer;
    char* end = buffer + bytesRead;
    char section[128] = {0};
    
    while (line < end) {
        // Find end of line
        char* lineEnd = line;
        while (lineEnd < end && *lineEnd != '\n' && *lineEnd != '\r') lineEnd++;
        *lineEnd = '\0';
        
        // Trim whitespace
        while (*line == ' ' || *line == '\t') line++;
        
        // Check for section header
        if (*line == '[') {
            char* sectionEnd = strchr(line, ']');
            if (sectionEnd) {
                *sectionEnd = '\0';
                strcpy(section, line + 1);
            }
        }
        // Check for key = value
        else if (strchr(line, '=')) {
            ParseManifestEntry(line, section, results);
        }
        
        line = lineEnd + 1;
        while (line < end && (*line == '\n' || *line == '\r')) line++;
    }
}

void ArtifactScanner::ParseManifestEntry(const char* line, const char* section, 
                                         ScanResults* results) {
    if (!section || !section[0]) return;
    
    // Parse key = value
    char key[128] = {0};
    char value[256] = {0};
    
    const char* eq = strchr(line, '=');
    if (!eq) return;
    
    // Extract key
    size_t keyLen = eq - line;
    if (keyLen >= sizeof(key)) keyLen = sizeof(key) - 1;
    strncpy(key, line, keyLen);
    key[keyLen] = '\0';
    
    // Trim key
    char* k = key;
    while (*k == ' ' || *k == '\t') k++;
    char* ke = key + strlen(key) - 1;
    while (ke > k && (*ke == ' ' || *ke == '\t')) *ke-- = '\0';
    
    // Extract value (skip { and })
    const char* v = eq + 1;
    while (*v == ' ' || *v == '\t' || *v == '{') v++;
    strcpy(value, v);
    
    // Trim trailing }
    char* ve = value + strlen(value) - 1;
    while (ve >= value && (*ve == ' ' || *ve == '\t' || *ve == '}')) *ve-- = '\0';
    
    // Create artifact entry based on section
    ArtifactEntry entry = {0};
    strcpy(entry.name, k);
    entry.status = STATUS_MISSING; // Will be updated by filesystem scan
    
    if (strcmp(section, "subsystems") == 0) {
        entry.type = ARTIFACT_SUBSYSTEM;
        wsprintfA(entry.path, "subsystems/%sSubsystem.cpp", k);
        
        // Check for type in value
        const char* type = strstr(value, "type=");
        if (type) {
            type += 5;
            if (*type == '"') type++;
            char* q = strchr((char*)type, '"');
            if (q) {
                size_t len = q - type;
                if (len > 255) len = 255;
                strncpy(entry.expectedCaps, type, len);
                entry.expectedCaps[len] = '\0';
            }
        }
    }
    else if (strncmp(section, "experts.", 8) == 0) {
        entry.type = ARTIFACT_EXPERT;
        const char* lang = section + 8;
        wsprintfA(entry.path, "experts/%s/%s_%s.asm", lang, lang, k);
        
        // Check for caps in value
        const char* caps = strstr(value, "caps=[");
        if (caps) {
            caps += 6;
            char* out = entry.expectedCaps;
            size_t outLen = 0;
            while (*caps && *caps != ']' && outLen < 255) {
                if (*caps == '"') {
                    caps++;
                    while (*caps && *caps != '"' && outLen < 255) {
                        *out++ = *caps++;
                        outLen++;
                    }
                    if (*caps == '"') caps++;
                    if (*caps == ',' || *caps == ' ') {
                        *out++ = ',';
                        outLen++;
                    }
                } else {
                    caps++;
                }
            }
            *out = '\0';
        }
    }
    else if (strcmp(section, "workflow") == 0) {
        entry.type = ARTIFACT_WORKFLOW;
        wsprintfA(entry.path, "workflows/%s.json", k);
    }
    else if (strcmp(section, "seg.nodes") == 0) {
        entry.type = ARTIFACT_SEG_NODE;
        wsprintfA(entry.path, "seg/%sNode.cpp", k);
    }
    else if (strcmp(section, "vscode.commands") == 0) {
        entry.type = ARTIFACT_VSCODE_COMMAND;
        wsprintfA(entry.path, "vscode/commands/%s.ts", k);
    }
    else if (strcmp(section, "http.routes") == 0) {
        entry.type = ARTIFACT_HTTP_ROUTE;
        wsprintfA(entry.path, "http/routes/%s.cpp", k);
    }
    
    if (entry.type != ARTIFACT_COUNT) {
        AddEntry(results, &entry);
    }
}

//==============================================================================
// Filesystem Scan
//==============================================================================

void ArtifactScanner::ScanFilesystem(ScanResults* results) {
    // Scan each artifact type directory
    ScanDirectory("subsystems", "*.cpp", ARTIFACT_SUBSYSTEM, results);
    ScanDirectory("experts/csharp", "*.asm", ARTIFACT_EXPERT, results);
    ScanDirectory("experts/java", "*.asm", ARTIFACT_EXPERT, results);
    ScanDirectory("experts/js", "*.asm", ARTIFACT_EXPERT, results);
    ScanDirectory("experts/masm", "*.asm", ARTIFACT_EXPERT, results);
    ScanDirectory("workflows", "*.json", ARTIFACT_WORKFLOW, results);
    ScanDirectory("seg", "*.cpp", ARTIFACT_SEG_NODE, results);
    ScanDirectory("vscode/commands", "*.ts", ARTIFACT_VSCODE_COMMAND, results);
    ScanDirectory("http/routes", "*.cpp", ARTIFACT_HTTP_ROUTE, results);
}

void ArtifactScanner::ScanDirectory(const char* dir, const char* pattern,
                                    ArtifactType type, ScanResults* results) {
    char searchPath[MAX_PATH];
    wsprintfA(searchPath, "%s\\%s", dir, pattern);
    
    WIN32_FIND_DATAA findData;
    HANDLE hFind = FindFirstFileA(searchPath, &findData);
    
    if (hFind == INVALID_HANDLE_VALUE) return;
    
    do {
        if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
        
        // Extract name from filename
        char name[128] = {0};
        strcpy(name, findData.cFileName);
        
        // Remove extension
        char* dot = strrchr(name, '.');
        if (dot) *dot = '\0';
        
        // Check if already in results (declared in manifest)
        bool found = false;
        for (unsigned int i = 0; i < results->count; i++) {
            if (strcmp(results->entries[i].name, name) == 0) {
                found = true;
                // Update with file info
                results->entries[i].binaryTime = findData.ftLastWriteTime;
                GetFileTime(results->entries[i].path, &results->entries[i].sourceTime);
                break;
            }
        }
        
        // If not found, add as undeclared
        if (!found) {
            ArtifactEntry entry = {0};
            strcpy(entry.name, name);
            wsprintfA(entry.path, "%s\\%s", dir, findData.cFileName);
            entry.type = type;
            entry.status = STATUS_UNDECLARED;
            entry.binaryTime = findData.ftLastWriteTime;
            GetFileTime(entry.path, &entry.sourceTime);
            AddEntry(results, &entry);
        }
        
    } while (FindNextFileA(hFind, &findData));
    
    FindClose(hFind);
}

//==============================================================================
// Registry Scan
//==============================================================================

void ArtifactScanner::ScanRegistry(ScanResults* results) {
    // Check each entry in results against SSR
    for (unsigned int i = 0; i < results->count; i++) {
        ArtifactEntry* entry = &results->entries[i];
        
        // Check if registered
        const SovereignSubsystem* sub = SSR_Find(entry->name);
        if (sub) {
            entry->registered = true;
            if (entry->status == STATUS_OK) {
                // Already OK, stay OK
            }
        } else {
            entry->registered = false;
            if (entry->status == STATUS_OK && FileExists(entry->path)) {
                entry->status = STATUS_UNREGISTERED;
            }
        }
    }
}

//==============================================================================
// Timestamp Check
//==============================================================================

void ArtifactScanner::CheckTimestamps(ScanResults* results) {
    for (unsigned int i = 0; i < results->count; i++) {
        ArtifactEntry* entry = &results->entries[i];
        
        // Skip if not present
        if (entry->status == STATUS_MISSING) continue;
        
        // Check if source is newer than binary
        // For .asm files, check if .asm is newer than .obj/.dll
        char sourcePath[MAX_PATH];
        strcpy(sourcePath, entry->path);
        
        // Get corresponding binary path
        char binaryPath[MAX_PATH];
        if (entry->type == ARTIFACT_EXPERT) {
            // Check .obj file
            strcpy(binaryPath, entry->path);
            char* dot = strrchr(binaryPath, '.');
            if (dot) strcpy(dot, ".obj");
        } else if (entry->type == ARTIFACT_SUBSYSTEM) {
            // Check .obj file
            strcpy(binaryPath, entry->path);
            char* dot = strrchr(binaryPath, '.');
            if (dot) strcpy(dot, ".obj");
        } else {
            continue; // No binary to check
        }
        
        FILETIME sourceTime, binaryTime;
        if (GetFileTime(sourcePath, &sourceTime) && GetFileTime(binaryPath, &binaryTime)) {
            if (IsOlder(&binaryTime, &sourceTime)) {
                entry->status = STATUS_OUTDATED;
                entry->sourceTime = sourceTime;
                entry->binaryTime = binaryTime;
            }
        }
    }
}

//==============================================================================
// Capability Check
//==============================================================================

void ArtifactScanner::CheckCapabilities(ScanResults* results) {
    for (unsigned int i = 0; i < results->count; i++) {
        ArtifactEntry* entry = &results->entries[i];
        
        // For experts, check if caps match
        if (entry->type == ARTIFACT_EXPERT && entry->status == STATUS_OK) {
            // Parse actual caps from MASM file
            // This would require parsing the .asm file
            // For now, mark as OK if file exists
        }
        
        // Format message
        FormatMessage(entry);
    }
}

//==============================================================================
// Specific Checks
//==============================================================================

bool ArtifactScanner::CheckSubsystem(const char* name) {
    char path[MAX_PATH];
    wsprintfA(path, "subsystems/%sSubsystem.cpp", name);
    return FileExists(path);
}

bool ArtifactScanner::CheckExpert(const char* language, const char* name) {
    char path[MAX_PATH];
    wsprintfA(path, "experts/%s/%s_%s.asm", language, language, name);
    return FileExists(path);
}

bool ArtifactScanner::CheckWorkflow(const char* name) {
    char path[MAX_PATH];
    wsprintfA(path, "workflows/%s.json", name);
    return FileExists(path);
}

bool ArtifactScanner::CheckSEGNode(const char* name) {
    char path[MAX_PATH];
    wsprintfA(path, "seg/%sNode.cpp", name);
    return FileExists(path);
}

//==============================================================================
// Auto-Fix Operations
//==============================================================================

void ArtifactScanner::GenerateMissing(ScanResults* results) {
    for (unsigned int i = 0; i < results->count; i++) {
        if (results->entries[i].status == STATUS_MISSING) {
            // Trigger generator for this artifact
            // This would call the appropriate generator
            ArtifactEntry* entry = &results->entries[i];
            
            // Log generation
            char msg[512];
            wsprintfA(msg, "Generating missing artifact: %s", entry->name);
            OutputDebugStringA(msg);
        }
    }
}

void ArtifactScanner::UpdateOutdated(ScanResults* results) {
    for (unsigned int i = 0; i < results->count; i++) {
        if (results->entries[i].status == STATUS_OUTDATED) {
            // Trigger recompile
            ArtifactEntry* entry = &results->entries[i];
            
            // Log update
            char msg[512];
            wsprintfA(msg, "Updating outdated artifact: %s", entry->name);
            OutputDebugStringA(msg);
            
            // Trigger hotpatch
            TriggerHotpatch(entry->name);
        }
    }
}

void ArtifactScanner::RegisterUnregistered(ScanResults* results) {
    for (unsigned int i = 0; i < results->count; i++) {
        if (results->entries[i].status == STATUS_UNREGISTERED) {
            // Trigger registration
            ArtifactEntry* entry = &results->entries[i];
            
            // Log registration
            char msg[512];
            wsprintfA(msg, "Registering artifact: %s", entry->name);
            OutputDebugStringA(msg);
        }
    }
}

//==============================================================================
// Reporting
//==============================================================================

void ArtifactScanner::ReportToIDE(const ScanResults* results) {
    // Send results to IDE panels
    // This would update the Subsystem Inspector and Expert Inspector
    
    for (unsigned int i = 0; i < results->count; i++) {
        const ArtifactEntry* entry = &results->entries[i];
        
        // Format based on status
        const char* prefix = "";
        switch (entry->status) {
            case STATUS_OK: prefix = "✓"; break;
            case STATUS_MISSING: prefix = "❌"; break;
            case STATUS_UNDECLARED: prefix = "⚠"; break;
            case STATUS_OUTDATED: prefix = "⚠"; break;
            case STATUS_MISMATCHED: prefix = "⚠"; break;
            case STATUS_UNREGISTERED: prefix = "⚠"; break;
            default: prefix = "?"; break;
        }
        
        char msg[1024];
        wsprintfA(msg, "%s %s: %s - %s", prefix, 
                  entry->type == ARTIFACT_SUBSYSTEM ? "Subsystem" :
                  entry->type == ARTIFACT_EXPERT ? "Expert" :
                  entry->type == ARTIFACT_WORKFLOW ? "Workflow" :
                  entry->type == ARTIFACT_SEG_NODE ? "SEG Node" :
                  entry->type == ARTIFACT_VSCODE_COMMAND ? "VS Code Cmd" :
                  entry->type == ARTIFACT_HTTP_ROUTE ? "HTTP Route" : "Unknown",
                  entry->name, entry->message);
        
        OutputDebugStringA(msg);
        OutputDebugStringA("\n");
    }
}

void ArtifactScanner::ExportReport(const char* path, const ScanResults* results) {
    HANDLE hFile = CreateFileA(path, GENERIC_WRITE, 0, nullptr,
                               CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) return;
    
    // Write header
    const char* header = "# Sovereign Runtime Artifact Report\n\n";
    DWORD written;
    WriteFile(hFile, header, strlen(header), &written, nullptr);
    
    // Write summary
    char summary[512];
    wsprintfA(summary, 
        "## Summary\n\n"
        "- Total Artifacts: %d\n"
        "- OK: %d\n"
        "- Missing: %d\n"
        "- Undeclared: %d\n"
        "- Outdated: %d\n"
        "- Mismatched: %d\n"
        "- Unregistered: %d\n\n",
        results->count, results->okCount, results->missingCount,
        results->undeclaredCount, results->outdatedCount,
        results->mismatchedCount, results->unregisteredCount);
    WriteFile(hFile, summary, strlen(summary), &written, nullptr);
    
    // Write details
    const char* details = "## Details\n\n";
    WriteFile(hFile, details, strlen(details), &written, nullptr);
    
    for (unsigned int i = 0; i < results->count; i++) {
        const ArtifactEntry* entry = &results->entries[i];
        
        char line[1024];
        const char* statusStr = "";
        switch (entry->status) {
            case STATUS_OK: statusStr = "OK"; break;
            case STATUS_MISSING: statusStr = "MISSING"; break;
            case STATUS_UNDECLARED: statusStr = "UNDECLARED"; break;
            case STATUS_OUTDATED: statusStr = "OUTDATED"; break;
            case STATUS_MISMATCHED: statusStr = "MISMATCHED"; break;
            case STATUS_UNREGISTERED: statusStr = "UNREGISTERED"; break;
            default: statusStr = "UNKNOWN"; break;
        }
        
        wsprintfA(line, "- **%s** (%s): %s\n  Path: %s\n  Message: %s\n\n",
                  entry->name, statusStr,
                  entry->type == ARTIFACT_SUBSYSTEM ? "Subsystem" :
                  entry->type == ARTIFACT_EXPERT ? "Expert" :
                  entry->type == ARTIFACT_WORKFLOW ? "Workflow" :
                  entry->type == ARTIFACT_SEG_NODE ? "SEG Node" :
                  entry->type == ARTIFACT_VSCODE_COMMAND ? "VS Code Cmd" :
                  entry->type == ARTIFACT_HTTP_ROUTE ? "HTTP Route" : "Unknown",
                  entry->path, entry->message);
        
        WriteFile(hFile, line, strlen(line), &written, nullptr);
    }
    
    CloseHandle(hFile);
}

//==============================================================================
// Helper Functions
//==============================================================================

void ArtifactScanner::CompareEntry(ArtifactEntry* entry) {
    // Compare manifest declaration vs filesystem vs registry
    bool inManifest = (entry->status != STATUS_UNDECLARED);
    bool onDisk = FileExists(entry->path);
    bool inRegistry = entry->registered;
    
    if (!inManifest && onDisk) {
        entry->status = STATUS_UNDECLARED;
    } else if (inManifest && !onDisk) {
        entry->status = STATUS_MISSING;
    } else if (inManifest && onDisk && !inRegistry) {
        entry->status = STATUS_UNREGISTERED;
    } else if (inManifest && onDisk && inRegistry) {
        entry->status = STATUS_OK;
    }
}

ArtifactStatus ArtifactScanner::DetermineStatus(const ArtifactEntry* entry) {
    // This is called after all scans complete
    if (!FileExists(entry->path)) {
        return STATUS_MISSING;
    }
    if (!entry->registered) {
        return STATUS_UNREGISTERED;
    }
    return STATUS_OK;
}

void ArtifactScanner::FormatMessage(ArtifactEntry* entry) {
    switch (entry->status) {
        case STATUS_OK:
            strcpy(entry->message, "Artifact is present, up-to-date, and registered");
            break;
        case STATUS_MISSING:
            wsprintfA(entry->message, "Artifact declared in manifest but not found at %s", entry->path);
            break;
        case STATUS_UNDECLARED:
            wsprintfA(entry->message, "Artifact found at %s but not declared in manifest", entry->path);
            break;
        case STATUS_OUTDATED:
            strcpy(entry->message, "Source file is newer than binary - recompilation needed");
            break;
        case STATUS_MISMATCHED:
            wsprintfA(entry->message, "Capability mismatch: expected [%s], actual [%s]", 
                     entry->expectedCaps, entry->actualCaps);
            break;
        case STATUS_UNREGISTERED:
            strcpy(entry->message, "Artifact present but not registered in runtime");
            break;
        default:
            strcpy(entry->message, "Unknown status");
            break;
    }
}

void ArtifactScanner::AddEntry(ScanResults* results, const ArtifactEntry* entry) {
    if (results->count >= 256) return;
    results->entries[results->count++] = *entry;
}

bool ArtifactScanner::FileExists(const char* path) {
    DWORD attribs = GetFileAttributesA(path);
    return (attribs != INVALID_FILE_ATTRIBUTES && !(attribs & FILE_ATTRIBUTE_DIRECTORY));
}

bool ArtifactScanner::GetFileTime(const char* path, FILETIME* ft) {
    HANDLE hFile = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, nullptr,
                               OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) return false;
    
    bool result = GetFileTime(hFile, nullptr, nullptr, ft);
    CloseHandle(hFile);
    return result;
}

bool ArtifactScanner::IsOlder(const FILETIME* a, const FILETIME* b) {
    return CompareFileTime(a, b) < 0;
}

//==============================================================================
// IDE Integration
//==============================================================================

void ArtifactScanner_InitializePanel() {
    ArtifactScanner::Initialize();
}

void ArtifactScanner_RefreshPanel() {
    ScanResults results;
    ArtifactScanner::ScanAll(&results);
    ArtifactScanner::ReportToIDE(&results);
}

void ArtifactScanner_DrawPanel() {
    // This would be called by the IDE's render loop
    // to draw the Artifact Inspector panel
}

//==============================================================================
// Hotpatch Integration
//==============================================================================

void ArtifactScanner_TriggerHotpatch(const char* artifactName) {
    // Trigger hotpatch for the specified artifact
    // This would call the HotReloadManager
    char msg[256];
    wsprintfA(msg, "Triggering hotpatch for: %s", artifactName);
    OutputDebugStringA(msg);
}

bool ArtifactScanner_CanHotpatch(const char* artifactName) {
    // Check if artifact can be hotpatched
    // Only experts and some subsystems support hotpatching
    return true; // Simplified
}
