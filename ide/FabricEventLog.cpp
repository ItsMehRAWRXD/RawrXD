#include "ide/FabricEventLog.hpp"
#include "ide/PanelState.hpp"
#include "sovereign/SubsystemStatus.hpp"
#include <imgui.h>
#include <vector>
#include <string>

struct LogEntry {
    uint64_t timestamp;
    std::string category;
    std::string message;
};

static std::vector<LogEntry> g_events;
static bool visible = false;

const char* FabricEventLog::Id() { return "FabricEventLog"; }
void FabricEventLog::Toggle() { PanelState::Toggle(Id()); }
bool FabricEventLog::IsWired() { return SubsystemStatus::AlwaysWired(); }

void FabricEventLog::Init() {
    PanelState::Register(Id());
}

void FabricEventLog::LogEvent(const char* category, const char* message) {
    LogEntry entry;
    entry.timestamp = 0; // Placeholder - would use actual timestamp
    entry.category = category;
    entry.message = message;
    g_events.push_back(entry);
    
    if (g_events.size() > 1000) {
        g_events.erase(g_events.begin());
    }
}

void FabricEventLog::Render() {
    if (!PanelState::Visible(Id())) return;

    ImGui::Begin("Fabric Event Log", &visible);

    ImGui::Text("Recent Events (%zu)", g_events.size());
    ImGui::Separator();

    ImGui::BeginChild("ScrollingRegion", ImVec2(0, 0), false, ImGuiWindowFlags_HorizontalScrollbar);
    
    for (auto it = g_events.rbegin(); it != g_events.rend() && std::distance(g_events.rbegin(), it) < 100; ++it) {
        ImVec4 color = ImVec4(1.0f, 1.0f, 1.0f, 1.0f);
        if (it->category == "ERROR") color = ImVec4(1.0f, 0.3f, 0.3f, 1.0f);
        else if (it->category == "WARN") color = ImVec4(1.0f, 1.0f, 0.3f, 1.0f);
        else if (it->category == "CONSENSUS") color = ImVec4(0.3f, 1.0f, 0.3f, 1.0f);
        
        ImGui::TextColored(color, "[%s] %s", it->category.c_str(), it->message.c_str());
    }
    
    ImGui::EndChild();

    ImGui::End();
}
