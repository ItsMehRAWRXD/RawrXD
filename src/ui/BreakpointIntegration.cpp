// ============================================================================
// Phase 25: BreakpointGutter-Debugger Integration Implementation
// ============================================================================

#include "ui/BreakpointIntegration.hpp"
#include <windows.h>
#include <fstream>
#include <nlohmann/json.hpp>

namespace RawrXD {
namespace UI {

// ============================================================================
// Static Member Definitions
// ============================================================================

BreakpointsGutter* BreakpointIntegration::s_gutter = nullptr;
std::wstring BreakpointIntegration::s_currentFile;
std::map<std::wstring, std::map<uint32_t, BreakpointMetadata>> BreakpointIntegration::s_breakpoints;
uint32_t BreakpointIntegration::s_nextBreakpointId = 1;
bool BreakpointIntegration::s_initialized = false;

// ============================================================================
// Public Interface
// ============================================================================

bool BreakpointIntegration::Initialize(BreakpointsGutter* gutter) {
    if (s_initialized) {
        return true;
    }
    
    if (!gutter) {
        return false;
    }
    
    s_gutter = gutter;
    s_initialized = true;
    
    // Register gutter callback
    gutter->SetBreakpointToggleCallback(OnGutterToggle);
    
    return true;
}

void BreakpointIntegration::Shutdown() {
    if (!s_initialized) {
        return;
    }
    
    // Save breakpoints before shutdown
    SaveBreakpoints();
    
    s_breakpoints.clear();
    s_gutter = nullptr;
    s_initialized = false;
}

bool BreakpointIntegration::IsInitialized() {
    return s_initialized && s_gutter != nullptr;
}

void BreakpointIntegration::SetCurrentFile(const std::wstring& filePath) {
    s_currentFile = filePath;
    
    // Refresh gutter to show breakpoints for this file
    if (s_gutter) {
        s_gutter->ClearAllBreakpoints();
        
        auto it = s_breakpoints.find(filePath);
        if (it != s_breakpoints.end()) {
            for (const auto& [line, bp] : it->second) {
                UpdateGutterVisuals(line, bp.state);
            }
        }
    }
}

std::wstring BreakpointIntegration::GetCurrentFile() {
    return s_currentFile;
}

bool BreakpointIntegration::ToggleBreakpoint(uint32_t lineNumber) {
    if (!s_initialized || s_currentFile.empty()) {
        return false;
    }
    
    auto& fileBps = s_breakpoints[s_currentFile];
    auto it = fileBps.find(lineNumber);
    
    if (it != fileBps.end()) {
        // Breakpoint exists - remove it
        ClearBreakpoint(lineNumber);
        return false;  // Indicates breakpoint was cleared
    } else {
        // Set new breakpoint
        return SetBreakpoint(lineNumber);
    }
}

bool BreakpointIntegration::SetBreakpoint(uint32_t lineNumber, const std::string& condition) {
    if (!s_initialized || s_currentFile.empty()) {
        return false;
    }
    
    // Create metadata
    BreakpointMetadata bp;
    bp.id = s_nextBreakpointId++;
    bp.filePath = s_currentFile;
    bp.lineNumber = lineNumber;
    bp.state = BreakpointLifecycleState::Pending;
    bp.condition = condition;
    bp.isEnabled = true;
    
    // Store in map
    s_breakpoints[s_currentFile][lineNumber] = bp;
    
    // Update gutter visuals
    UpdateGutterVisuals(lineNumber, BreakpointLifecycleState::Pending);
    
    // If debugger is active, send to DapService
    if (Win32IDE_DebuggerIntegration::IsDebugging()) {
        std::string fileStr(s_currentFile.begin(), s_currentFile.end());
        Win32IDE_DebuggerIntegration::SetBreakpoint(fileStr, lineNumber);
    }
    
    return true;
}

bool BreakpointIntegration::ClearBreakpoint(uint32_t lineNumber) {
    if (!s_initialized || s_currentFile.empty()) {
        return false;
    }
    
    auto fileIt = s_breakpoints.find(s_currentFile);
    if (fileIt == s_breakpoints.end()) {
        return false;
    }
    
    auto bpIt = fileIt->second.find(lineNumber);
    if (bpIt == fileIt->second.end()) {
        return false;
    }
    
    // Clear from gutter
    if (s_gutter) {
        s_gutter->ClearBreakpointState(lineNumber);
    }
    
    // Remove from map
    fileIt->second.erase(bpIt);
    
    // Clean up empty file entries
    if (fileIt->second.empty()) {
        s_breakpoints.erase(fileIt);
    }
    
    return true;
}

void BreakpointIntegration::ClearAllBreakpointsInCurrentFile() {
    if (!s_initialized || s_currentFile.empty()) {
        return;
    }
    
    auto it = s_breakpoints.find(s_currentFile);
    if (it != s_breakpoints.end()) {
        // Clear all from gutter
        if (s_gutter) {
            for (const auto& [line, bp] : it->second) {
                s_gutter->ClearBreakpointState(line);
            }
        }
        
        s_breakpoints.erase(it);
    }
}

void BreakpointIntegration::ClearAllBreakpoints() {
    if (!s_initialized) {
        return;
    }
    
    // Clear all from gutter
    if (s_gutter) {
        s_gutter->ClearAllBreakpoints();
    }
    
    s_breakpoints.clear();
}

void BreakpointIntegration::SetBreakpointEnabled(uint32_t lineNumber, bool enabled) {
    if (!s_initialized || s_currentFile.empty()) {
        return;
    }
    
    auto fileIt = s_breakpoints.find(s_currentFile);
    if (fileIt == s_breakpoints.end()) {
        return;
    }
    
    auto bpIt = fileIt->second.find(lineNumber);
    if (bpIt == fileIt->second.end()) {
        return;
    }
    
    bpIt->second.isEnabled = enabled;
    
    // Update visual state
    if (enabled) {
        bpIt->second.state = BreakpointLifecycleState::Verified;
        UpdateGutterVisuals(lineNumber, BreakpointLifecycleState::Verified);
    } else {
        bpIt->second.state = BreakpointLifecycleState::Disabled;
        UpdateGutterVisuals(lineNumber, BreakpointLifecycleState::Disabled);
    }
}

bool BreakpointIntegration::HasBreakpoint(uint32_t lineNumber) {
    if (!s_initialized || s_currentFile.empty()) {
        return false;
    }
    
    auto fileIt = s_breakpoints.find(s_currentFile);
    if (fileIt == s_breakpoints.end()) {
        return false;
    }
    
    return fileIt->second.find(lineNumber) != fileIt->second.end();
}

BreakpointLifecycleState BreakpointIntegration::GetBreakpointState(uint32_t lineNumber) {
    if (!s_initialized || s_currentFile.empty()) {
        return BreakpointLifecycleState::None;
    }
    
    auto fileIt = s_breakpoints.find(s_currentFile);
    if (fileIt == s_breakpoints.end()) {
        return BreakpointLifecycleState::None;
    }
    
    auto bpIt = fileIt->second.find(lineNumber);
    if (bpIt == fileIt->second.end()) {
        return BreakpointLifecycleState::None;
    }
    
    return bpIt->second.state;
}

void BreakpointIntegration::OnBreakpointVerified(uint32_t lineNumber, uint32_t actualLine,
                                                   bool verified, uint32_t breakpointId) {
    if (!s_initialized) {
        return;
    }
    
    // Find the pending breakpoint
    for (auto& [file, fileBps] : s_breakpoints) {
        for (auto& [line, bp] : fileBps) {
            if (bp.state == BreakpointLifecycleState::Pending) {
                if (verified) {
                    bp.state = BreakpointLifecycleState::Verified;
                    bp.id = breakpointId;
                    
                    // If actual line differs, update
                    if (actualLine != line) {
                        fileBps.erase(line);
                        bp.lineNumber = actualLine;
                        fileBps[actualLine] = bp;
                        UpdateGutterVisuals(actualLine, BreakpointLifecycleState::Verified);
                    } else {
                        UpdateGutterVisuals(line, BreakpointLifecycleState::Verified);
                    }
                } else {
                    bp.state = BreakpointLifecycleState::Failed;
                    bp.errorMessage = "Failed to verify breakpoint";
                    UpdateGutterVisuals(line, BreakpointLifecycleState::Failed);
                }
                return;
            }
        }
    }
}

void BreakpointIntegration::OnBreakpointHit(uint32_t lineNumber) {
    if (!s_initialized) {
        return;
    }
    
    // Update state
    auto fileIt = s_breakpoints.find(s_currentFile);
    if (fileIt != s_breakpoints.end()) {
        auto bpIt = fileIt->second.find(lineNumber);
        if (bpIt != fileIt->second.end()) {
            bpIt->second.state = BreakpointLifecycleState::Hit;
        }
    }
    
    // Update gutter
    if (s_gutter) {
        s_gutter->SetCurrentLine(lineNumber);
    }
}

void BreakpointIntegration::ClearHitIndicator() {
    if (!s_initialized) {
        return;
    }
    
    // Clear hit state from all breakpoints
    for (auto& [file, fileBps] : s_breakpoints) {
        for (auto& [line, bp] : fileBps) {
            if (bp.state == BreakpointLifecycleState::Hit) {
                bp.state = bp.isEnabled ? BreakpointLifecycleState::Verified 
                                        : BreakpointLifecycleState::Disabled;
            }
        }
    }
    
    // Clear from gutter
    if (s_gutter) {
        s_gutter->ClearCurrentLine();
    }
}

std::vector<BreakpointMetadata> BreakpointIntegration::GetBreakpointsInCurrentFile() {
    std::vector<BreakpointMetadata> result;
    
    if (!s_initialized || s_currentFile.empty()) {
        return result;
    }
    
    auto it = s_breakpoints.find(s_currentFile);
    if (it != s_breakpoints.end()) {
        for (const auto& [line, bp] : it->second) {
            result.push_back(bp);
        }
    }
    
    return result;
}

void BreakpointIntegration::SaveBreakpoints() {
    if (!s_initialized) {
        return;
    }
    
    // TODO: Implement session persistence
    // For now, breakpoints are in-memory only
}

void BreakpointIntegration::LoadBreakpoints() {
    if (!s_initialized) {
        return;
    }
    
    // TODO: Implement session restoration
    // For now, breakpoints are in-memory only
}

// ============================================================================
// Private Helpers
// ============================================================================

void BreakpointIntegration::UpdateGutterVisuals(uint32_t lineNumber, BreakpointLifecycleState state) {
    if (!s_gutter) {
        return;
    }
    
    BreakpointVisualState visualState = LifecycleToVisual(state);
    s_gutter->SetBreakpointState(lineNumber, visualState);
}

BreakpointVisualState BreakpointIntegration::LifecycleToVisual(BreakpointLifecycleState state) {
    switch (state) {
        case BreakpointLifecycleState::Pending:
        case BreakpointLifecycleState::Verified:
            return BreakpointVisualState::Enabled;
            
        case BreakpointLifecycleState::Disabled:
            return BreakpointVisualState::Disabled;
            
        case BreakpointLifecycleState::Hit:
            return BreakpointVisualState::Hit;
            
        case BreakpointLifecycleState::Failed:
            return BreakpointVisualState::Disabled;  // Show as disabled
            
        default:
            return BreakpointVisualState::None;
    }
}

void BreakpointIntegration::OnGutterToggle(const std::wstring& filePath, uint32_t lineNumber) {
    // This is called when user clicks the gutter
    // The gutter already knows the file, so we just toggle
    if (filePath == s_currentFile) {
        ToggleBreakpoint(lineNumber);
    }
}

} // namespace UI
} // namespace RawrXD
