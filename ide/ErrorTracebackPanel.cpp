#include "ide/ErrorTracebackPanel.hpp"
#include "ide/PanelState.hpp"
#include "sovereign/SubsystemStatus.hpp"
#include <imgui.h>
#include <vector>
#include <string>

struct ErrorEntry {
    uint64_t timestamp;
    std::string subsystem;
    std::string error;
    std::string traceback;
    bool resolved;
};

static std::vector<ErrorEntry> g_errors;
static bool visible = false;

const char* ErrorTracebackPanel::Id() { return "ErrorTracebackPanel"; }
void ErrorTracebackPanel::Toggle() { PanelState::Toggle(Id()); }
bool ErrorTracebackPanel::IsWired() { return SubsystemStatus::AlwaysWired(); }

void ErrorTracebackPanel::Init() {
    PanelState::Register(Id());
}

void ErrorTracebackPanel::ReportError(const char* subsystem, const char* error, const char* traceback) {
    ErrorEntry entry;
    entry.timestamp = 0;
    entry.subsystem = subsystem;
    entry.error = error;
    entry.traceback = traceback;
    entry.resolved = false;
    g_errors.push_back(entry);
    
    if (g_errors.size() > 100) {
        g_errors.erase(g_errors.begin());
    }
}

void ErrorTracebackPanel::Render() {
    if (!PanelState::Visible(Id())) return;

    ImGui::Begin("Distributed Error Traceback", &visible);

    int unresolved = 0;
    for (const auto& e : g_errors) if (!e.resolved) unresolved++;
    
    if (unresolved > 0) {
        ImGui::TextColored(ImVec4(1.0f, 0.2f, 0.2f, 1.0f), "⚠ %d Unresolved Errors", unresolved);
    } else {
        ImGui::TextColored(ImVec4(0.2f, 1.0f, 0.2f, 1.0f), "✓ All Errors Resolved");
    }
    ImGui::Separator();

    for (size_t i = 0; i < g_errors.size() && i < 50; i++) {
        auto& e = g_errors[g_errors.size() - 1 - i];
        
        ImVec4 color = e.resolved ? ImVec4(0.5f, 0.5f, 0.5f, 1.0f) : ImVec4(1.0f, 0.3f, 0.3f, 1.0f);
        ImGui::PushStyleColor(ImGuiCol_Text, color);
        
        if (ImGui::CollapsingHeader(e.subsystem.c_str())) {
            ImGui::Text("Error: %s", e.error.c_str());
            ImGui::TextWrapped("Traceback: %s", e.traceback.c_str());
            
            if (!e.resolved) {
                if (ImGui::Button("Mark Resolved")) {
                    e.resolved = true;
                }
            }
        }
        
        ImGui::PopStyleColor();
    }

    ImGui::End();
}
