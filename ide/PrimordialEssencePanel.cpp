#include "PrimordialEssencePanel.hpp"
#include "../primordial/PrimordialEssenceEngine.hpp"
#include "../primordial/PrimordialEssenceLoop.hpp"
#include <imgui.h>
#include <algorithm>

namespace IDE {

PrimordialEssencePanel::PrimordialEssencePanel()
    : m_initialized(false)
    , m_visible(false)
    , m_currentTab(0)
{
    ClearInputBuffers();
    memset(m_filterBuffer, 0, sizeof(m_filterBuffer));
}

PrimordialEssencePanel::~PrimordialEssencePanel() {
    if (m_initialized) {
        Shutdown();
    }
}

bool PrimordialEssencePanel::Initialize() {
    if (m_initialized) return true;
    m_initialized = true;
    return true;
}

void PrimordialEssencePanel::Shutdown() {
    if (!m_initialized) return;
    m_initialized = false;
}

bool PrimordialEssencePanel::IsInitialized() const {
    return m_initialized;
}

void PrimordialEssencePanel::Show() {
    m_visible = true;
}

void PrimordialEssencePanel::Hide() {
    m_visible = false;
}

void PrimordialEssencePanel::ToggleVisibility() {
    m_visible = !m_visible;
}

bool PrimordialEssencePanel::IsVisible() const {
    return m_visible;
}

void PrimordialEssencePanel::Render() {
    if (!m_visible || !m_initialized) return;
    RenderWindow();
}

void PrimordialEssencePanel::RenderWindow() {
    ImGui::SetNextWindowSize(ImVec2(900, 700), ImGuiCond_FirstUseEver);
    
    if (ImGui::Begin("Primordial Essence (Layer 111)", &m_visible)) {
        RenderTabBar();
        
        switch (static_cast<Tab>(m_currentTab)) {
            case Tab::PrimordialStructures:
                RenderPrimordialStructuresTab();
                break;
            case Tab::OriginAbsolutes:
                RenderOriginAbsolutesTab();
                break;
            case Tab::SourceAbsolutes:
                RenderSourceAbsolutesTab();
                break;
            case Tab::RootAbsolutes:
                RenderRootAbsolutesTab();
                break;
            case Tab::FoundationAbsolutes:
                RenderFoundationAbsolutesTab();
                break;
            case Tab::GroundAbsolutes:
                RenderGroundAbsolutesTab();
                break;
            case Tab::Metrics:
                RenderMetricsTab();
                break;
            case Tab::Settings:
                RenderSettingsTab();
                break;
            default:
                break;
        }
    }
    ImGui::End();
}

void PrimordialEssencePanel::RenderTabBar() {
    if (ImGui::BeginTabBar("PrimordialEssenceTabs")) {
        if (ImGui::BeginTabItem("Primordial Structures")) {
            m_currentTab = static_cast<int>(Tab::PrimordialStructures);
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("Origin Absolutes")) {
            m_currentTab = static_cast<int>(Tab::OriginAbsolutes);
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("Source Absolutes")) {
            m_currentTab = static_cast<int>(Tab::SourceAbsolutes);
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("Root Absolutes")) {
            m_currentTab = static_cast<int>(Tab::RootAbsolutes);
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("Foundation Absolutes")) {
            m_currentTab = static_cast<int>(Tab::FoundationAbsolutes);
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("Ground Absolutes")) {
            m_currentTab = static_cast<int>(Tab::GroundAbsolutes);
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("Metrics")) {
            m_currentTab = static_cast<int>(Tab::Metrics);
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("Settings")) {
            m_currentTab = static_cast<int>(Tab::Settings);
            ImGui::EndTabItem();
        }
        ImGui::EndTabBar();
    }
}

void PrimordialEssencePanel::RenderPrimordialStructuresTab() {
    ImGui::Text("Primordial Essence Structures");
    ImGui::Separator();
    
    ImGui::InputText("Filter", m_filterBuffer, sizeof(m_filterBuffer));
    ImGui::SameLine();
    if (ImGui::Button("Create New")) {
        CreateNewPrimordialStructure();
    }
    
    ImGui::Spacing();
    
    auto structures = PrimordialEssence::PrimordialEssenceEngine::GetAllPrimordialEssenceStructures();
    
    if (ImGui::BeginTable("PrimordialStructuresTable", 4, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg)) {
        ImGui::TableSetupColumn("Name");
        ImGui::TableSetupColumn("Primordiality");
        ImGui::TableSetupColumn("Status");
        ImGui::TableSetupColumn("Actions");
        ImGui::TableHeadersRow();
        
        for (auto& structure : structures) {
            if (!FilterMatches(structure.name)) continue;
            
            ImGui::TableNextRow();
            
            ImGui::TableSetColumnIndex(0);
            if (ImGui::Selectable(structure.name.c_str(), m_selectedPrimordialId == structure.primordialId, 
                                  ImGuiSelectableFlags_SpanAllColumns)) {
                SelectPrimordialStructure(structure.primordialId);
            }
            
            ImGui::TableSetColumnIndex(1);
            ImGui::ProgressBar(structure.primordiality);
            
            ImGui::TableSetColumnIndex(2);
            if (structure.isPrimordial) {
                ImGui::TextColored(ImVec4(0, 1, 0, 1), "PRIMORDIAL");
            } else if (structure.isActive) {
                ImGui::Text("Active");
            } else {
                ImGui::TextDisabled("Inactive");
            }
            
            ImGui::TableSetColumnIndex(3);
            ImGui::PushID(structure.primordialId.c_str());
            if (ImGui::SmallButton("Deepen")) {
                OnDeepenPrimordiality(structure.primordialId);
            }
            ImGui::SameLine();
            if (ImGui::SmallButton("Delete")) {
                PrimordialEssence::PrimordialEssenceEngine::DestroyPrimordialEssenceStructure(structure.primordialId);
            }
            ImGui::PopID();
        }
        
        ImGui::EndTable();
    }
    
    if (!m_selectedPrimordialId.empty()) {
        RenderPrimordialStructureDetails(m_selectedPrimordialId);
    }
}

void PrimordialEssencePanel::RenderOriginAbsolutesTab() {
    ImGui::Text("Origin Absolutes");
    ImGui::Separator();
    
    ImGui::InputText("Filter", m_filterBuffer, sizeof(m_filterBuffer));
    ImGui::SameLine();
    if (ImGui::Button("Create New")) {
        CreateNewOriginAbsolute();
    }
    
    ImGui::Spacing();
    
    auto origins = PrimordialEssence::PrimordialEssenceEngine::GetAllOriginAbsolutes();
    
    if (ImGui::BeginTable("OriginAbsolutesTable", 4, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg)) {
        ImGui::TableSetupColumn("Name");
        ImGui::TableSetupColumn("Origin");
        ImGui::TableSetupColumn("Status");
        ImGui::TableSetupColumn("Actions");
        ImGui::TableHeadersRow();
        
        for (auto& origin : origins) {
            if (!FilterMatches(origin.name)) continue;
            
            ImGui::TableNextRow();
            
            ImGui::TableSetColumnIndex(0);
            if (ImGui::Selectable(origin.name.c_str(), m_selectedOriginId == origin.originId,
                                  ImGuiSelectableFlags_SpanAllColumns)) {
                SelectOriginAbsolute(origin.originId);
            }
            
            ImGui::TableSetColumnIndex(1);
            ImGui::ProgressBar(origin.origin);
            
            ImGui::TableSetColumnIndex(2);
            if (origin.isOriginated) {
                ImGui::TextColored(ImVec4(0, 1, 0, 1), "ORIGINATED");
            } else {
                ImGui::Text("Forming");
            }
            
            ImGui::TableSetColumnIndex(3);
            ImGui::PushID(origin.originId.c_str());
            if (ImGui::SmallButton("Commence")) {
                OnCommenceBeginning(origin.originId);
            }
            ImGui::SameLine();
            if (ImGui::SmallButton("Delete")) {
                PrimordialEssence::PrimordialEssenceEngine::DestroyOriginAbsolute(origin.originId);
            }
            ImGui::PopID();
        }
        
        ImGui::EndTable();
    }
    
    if (!m_selectedOriginId.empty()) {
        RenderOriginAbsoluteDetails(m_selectedOriginId);
    }
}

void PrimordialEssencePanel::RenderSourceAbsolutesTab() {
    ImGui::Text("Source Absolutes");
    ImGui::Separator();
    
    ImGui::InputText("Filter", m_filterBuffer, sizeof(m_filterBuffer));
    ImGui::SameLine();
    if (ImGui::Button("Create New")) {
        CreateNewSourceAbsolute();
    }
    
    ImGui::Spacing();
    
    auto sources = PrimordialEssence::PrimordialEssenceEngine::GetAllSourceAbsolutes();
    
    if (ImGui::BeginTable("SourceAbsolutesTable", 4, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg)) {
        ImGui::TableSetupColumn("Name");
        ImGui::TableSetupColumn("Source");
        ImGui::TableSetupColumn("Status");
        ImGui::TableSetupColumn("Actions");
        ImGui::TableHeadersRow();
        
        for (auto& source : sources) {
            if (!FilterMatches(source.name)) continue;
            
            ImGui::TableNextRow();
            
            ImGui::TableSetColumnIndex(0);
            if (ImGui::Selectable(source.name.c_str(), m_selectedSourceId == source.sourceId,
                                  ImGuiSelectableFlags_SpanAllColumns)) {
                SelectSourceAbsolute(source.sourceId);
            }
            
            ImGui::TableSetColumnIndex(1);
            ImGui::ProgressBar(source.source);
            
            ImGui::TableSetColumnIndex(2);
            if (source.isSourced) {
                ImGui::TextColored(ImVec4(0, 1, 0, 1), "SOURCED");
            } else {
                ImGui::Text("Forming");
            }
            
            ImGui::TableSetColumnIndex(3);
            ImGui::PushID(source.sourceId.c_str());
            if (ImGui::SmallButton("Open")) {
                OnOpenWellspring(source.sourceId);
            }
            ImGui::SameLine();
            if (ImGui::SmallButton("Delete")) {
                PrimordialEssence::PrimordialEssenceEngine::DestroySourceAbsolute(source.sourceId);
            }
            ImGui::PopID();
        }
        
        ImGui::EndTable();
    }
    
    if (!m_selectedSourceId.empty()) {
        RenderSourceAbsoluteDetails(m_selectedSourceId);
    }
}

void PrimordialEssencePanel::RenderRootAbsolutesTab() {
    ImGui::Text("Root Absolutes");
    ImGui::Separator();
    
    ImGui::InputText("Filter", m_filterBuffer, sizeof(m_filterBuffer));
    ImGui::SameLine();
    if (ImGui::Button("Create New")) {
        CreateNewRootAbsolute();
    }
    
    ImGui::Spacing();
    
    auto roots = PrimordialEssence::PrimordialEssenceEngine::GetAllRootAbsolutes();
    
    if (ImGui::BeginTable("RootAbsolutesTable", 4, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg)) {
        ImGui::TableSetupColumn("Name");
        ImGui::TableSetupColumn("Root");
        ImGui::TableSetupColumn("Status");
        ImGui::TableSetupColumn("Actions");
        ImGui::TableHeadersRow();
        
        for (auto& root : roots) {
            if (!FilterMatches(root.name)) continue;
            
            ImGui::TableNextRow();
            
            ImGui::TableSetColumnIndex(0);
            if (ImGui::Selectable(root.name.c_str(), m_selectedRootId == root.rootId,
                                  ImGuiSelectableFlags_SpanAllColumns)) {
                SelectRootAbsolute(root.rootId);
            }
            
            ImGui::TableSetColumnIndex(1);
            ImGui::ProgressBar(root.root);
            
            ImGui::TableSetColumnIndex(2);
            if (root.isRooted) {
                ImGui::TextColored(ImVec4(0, 1, 0, 1), "ROOTED");
            } else {
                ImGui::Text("Forming");
            }
            
            ImGui::TableSetColumnIndex(3);
            ImGui::PushID(root.rootId.c_str());
            if (ImGui::SmallButton("Strengthen")) {
                OnStrengthenBasis(root.rootId);
            }
            ImGui::SameLine();
            if (ImGui::SmallButton("Delete")) {
                PrimordialEssence::PrimordialEssenceEngine::DestroyRootAbsolute(root.rootId);
            }
            ImGui::PopID();
        }
        
        ImGui::EndTable();
    }
    
    if (!m_selectedRootId.empty()) {
        RenderRootAbsoluteDetails(m_selectedRootId);
    }
}

void PrimordialEssencePanel::RenderFoundationAbsolutesTab() {
    ImGui::Text("Foundation Absolutes");
    ImGui::Separator();
    
    ImGui::InputText("Filter", m_filterBuffer, sizeof(m_filterBuffer));
    ImGui::SameLine();
    if (ImGui::Button("Create New")) {
        CreateNewFoundationAbsolute();
    }
    
    ImGui::Spacing();
    
    auto foundations = PrimordialEssence::PrimordialEssenceEngine::GetAllFoundationAbsolutes();
    
    if (ImGui::BeginTable("FoundationAbsolutesTable", 4, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg)) {
        ImGui::TableSetupColumn("Name");
        ImGui::TableSetupColumn("Foundation");
        ImGui::TableSetupColumn("Status");
        ImGui::TableSetupColumn("Actions");
        ImGui::TableHeadersRow();
        
        for (auto& foundation : foundations) {
            if (!FilterMatches(foundation.name)) continue;
            
            ImGui::TableNextRow();
            
            ImGui::TableSetColumnIndex(0);
            if (ImGui::Selectable(foundation.name.c_str(), m_selectedFoundationId == foundation.foundationId,
                                  ImGuiSelectableFlags_SpanAllColumns)) {
                SelectFoundationAbsolute(foundation.foundationId);
            }
            
            ImGui::TableSetColumnIndex(1);
            ImGui::ProgressBar(foundation.foundation);
            
            ImGui::TableSetColumnIndex(2);
            if (foundation.isFounded) {
                ImGui::TextColored(ImVec4(0, 1, 0, 1), "FOUNDED");
            } else {
                ImGui::Text("Forming");
            }
            
            ImGui::TableSetColumnIndex(3);
            ImGui::PushID(foundation.foundationId.c_str());
            if (ImGui::SmallButton("Prepare")) {
                OnPrepareGroundwork(foundation.foundationId);
            }
            ImGui::SameLine();
            if (ImGui::SmallButton("Delete")) {
                PrimordialEssence::PrimordialEssenceEngine::DestroyFoundationAbsolute(foundation.foundationId);
            }
            ImGui::PopID();
        }
        
        ImGui::EndTable();
    }
    
    if (!m_selectedFoundationId.empty()) {
        RenderFoundationAbsoluteDetails(m_selectedFoundationId);
    }
}

void PrimordialEssencePanel::RenderGroundAbsolutesTab() {
    ImGui::Text("Ground Absolutes");
    ImGui::Separator();
    
    ImGui::InputText("Filter", m_filterBuffer, sizeof(m_filterBuffer));
    ImGui::SameLine();
    if (ImGui::Button("Create New")) {
        CreateNewGroundAbsolute();
    }
    
    ImGui::Spacing();
    
    auto grounds = PrimordialEssence::PrimordialEssenceEngine::GetAllGroundAbsolutes();
    
    if (ImGui::BeginTable("GroundAbsolutesTable", 4, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg)) {
        ImGui::TableSetupColumn("Name");
        ImGui::TableSetupColumn("Ground");
        ImGui::TableSetupColumn("Status");
        ImGui::TableSetupColumn("Actions");
        ImGui::TableHeadersRow();
        
        for (auto& ground : grounds) {
            if (!FilterMatches(ground.name)) continue;
            
            ImGui::TableNextRow();
            
            ImGui::TableSetColumnIndex(0);
            if (ImGui::Selectable(ground.name.c_str(), m_selectedGroundId == ground.groundId,
                                  ImGuiSelectableFlags_SpanAllColumns)) {
                SelectGroundAbsolute(ground.groundId);
            }
            
            ImGui::TableSetColumnIndex(1);
            ImGui::ProgressBar(ground.ground);
            
            ImGui::TableSetColumnIndex(2);
            if (ground.isGrounded) {
                ImGui::TextColored(ImVec4(0, 1, 0, 1), "GROUNDED");
            } else {
                ImGui::Text("Forming");
            }
            
            ImGui::TableSetColumnIndex(3);
            ImGui::PushID(ground.groundId.c_str());
            if (ImGui::SmallButton("Cultivate")) {
                OnCultivateSoil(ground.groundId);
            }
            ImGui::SameLine();
            if (ImGui::SmallButton("Delete")) {
                PrimordialEssence::PrimordialEssenceEngine::DestroyGroundAbsolute(ground.groundId);
            }
            ImGui::PopID();
        }
        
        ImGui::EndTable();
    }
    
    if (!m_selectedGroundId.empty()) {
        RenderGroundAbsoluteDetails(m_selectedGroundId);
    }
}

void PrimordialEssencePanel::RenderMetricsTab() {
    ImGui::Text("Primordial Essence Metrics");
    ImGui::Separator();
    
    auto metrics = PrimordialEssence::PrimordialEssenceEngine::GetPrimordialEssenceMetrics();
    auto loopMetrics = PrimordialEssence::PrimordialEssenceLoop::GetMetrics();
    
    ImGui::Columns(2, "MetricsColumns");
    
    ImGui::Text("Structures:");
    ImGui::Text("  Primordial Structures: %d", metrics.value("primordialStructureCount", 0));
    ImGui::Text("  Origin Absolutes: %d", metrics.value("originAbsoluteCount", 0));
    ImGui::Text("  Source Absolutes: %d", metrics.value("sourceAbsoluteCount", 0));
    ImGui::Text("  Root Absolutes: %d", metrics.value("rootAbsoluteCount", 0));
    ImGui::Text("  Foundation Absolutes: %d", metrics.value("foundationAbsoluteCount", 0));
    ImGui::Text("  Ground Absolutes: %d", metrics.value("groundAbsoluteCount", 0));
    
    ImGui::NextColumn();
    
    ImGui::Text("Performance:");
    ImGui::Text("  Current TPS: %.1f", loopMetrics.currentTPS);
    ImGui::Text("  Current FPS: %.1f", loopMetrics.currentFPS);
    ImGui::Text("  Total Ticks: %lld", loopMetrics.totalTicks);
    ImGui::Text("  Total Frames: %lld", loopMetrics.totalFrames);
    ImGui::Text("  Avg Tick Time: %.2f ms", loopMetrics.averageTickTimeMs);
    ImGui::Text("  Avg Frame Time: %.2f ms", loopMetrics.averageFrameTimeMs);
    
    ImGui::Columns(1);
    
    ImGui::Separator();
    ImGui::Text("Primordial Values:");
    
    float totalPrimordiality = metrics.value("totalPrimordiality", 0.0f);
    float totalOrigin = metrics.value("totalOrigin", 0.0f);
    float totalSource = metrics.value("totalSource", 0.0f);
    float totalRoot = metrics.value("totalRoot", 0.0f);
    float totalFoundation = metrics.value("totalFoundation", 0.0f);
    float totalGround = metrics.value("totalGround", 0.0f);
    
    ImGui::Text("Total Primordiality: %.2f", totalPrimordiality);
    ImGui::Text("Total Origin: %.2f", totalOrigin);
    ImGui::Text("Total Source: %.2f", totalSource);
    ImGui::Text("Total Root: %.2f", totalRoot);
    ImGui::Text("Total Foundation: %.2f", totalFoundation);
    ImGui::Text("Total Ground: %.2f", totalGround);
}

void PrimordialEssencePanel::RenderSettingsTab() {
    ImGui::Text("Primordial Essence Settings");
    ImGui::Separator();
    
    auto config = PrimordialEssence::PrimordialEssenceLoop::GetConfig();
    
    ImGui::SliderInt("Target TPS", &config.targetTPS, 1, 120);
    ImGui::SliderInt("Max FPS", &config.maxFPS, 1, 240);
    ImGui::Checkbox("Enable Frame Limiting", &config.enableFrameLimiting);
    ImGui::Checkbox("Enable Metrics", &config.enableMetrics);
    
    if (ImGui::Button("Apply Settings")) {
        PrimordialEssence::PrimordialEssenceLoop::SetConfig(config);
    }
}

void PrimordialEssencePanel::RenderPrimordialStructureDetails(const std::string& primordialId) {
    auto structure = PrimordialEssence::PrimordialEssenceEngine::GetPrimordialEssenceStructure(primordialId);
    if (!structure) return;
    
    ImGui::Separator();
    ImGui::Text("Details: %s", structure->name.c_str());
    
    ImGui::Text("Primordiality: %.2f", structure->primordiality);
    ImGui::ProgressBar(structure->primordiality);
    
    ImGui::Text("Origin: %.2f", structure->origin);
    ImGui::ProgressBar(structure->origin);
    
    ImGui::Text("Source: %.2f", structure->source);
    ImGui::ProgressBar(structure->source);
    
    ImGui::Text("Root: %.2f", structure->root);
    ImGui::ProgressBar(structure->root);
    
    ImGui::Text("Foundation: %.2f", structure->foundation);
    ImGui::ProgressBar(structure->foundation);
    
    ImGui::Text("Ground: %.2f", structure->ground);
    ImGui::ProgressBar(structure->ground);
    
    if (ImGui::Button("Deepen Primordiality")) OnDeepenPrimordiality(primordialId);
    ImGui::SameLine();
    if (ImGui::Button("Trace Origin")) OnTraceOrigin(primordialId);
    ImGui::SameLine();
    if (ImGui::Button("Tap Source")) OnTapSource(primordialId);
    ImGui::SameLine();
    if (ImGui::Button("Extend Root")) OnExtendRoot(primordialId);
    ImGui::SameLine();
    if (ImGui::Button("Lay Foundation")) OnLayFoundation(primordialId);
    ImGui::SameLine();
    if (ImGui::Button("Establish Ground")) OnEstablishGround(primordialId);
}

void PrimordialEssencePanel::RenderOriginAbsoluteDetails(const std::string& originId) {
    auto origin = PrimordialEssence::PrimordialEssenceEngine::GetOriginAbsolute(originId);
    if (!origin) return;
    
    ImGui::Separator();
    ImGui::Text("Details: %s", origin->name.c_str());
    
    ImGui::Text("Origin: %.2f", origin->origin);
    ImGui::ProgressBar(origin->origin);
    
    ImGui::Text("Beginning: %.2f", origin->beginning);
    ImGui::ProgressBar(origin->beginning);
    
    ImGui::Text("Inception: %.2f", origin->inception);
    ImGui::ProgressBar(origin->inception);
    
    if (ImGui::Button("Commence Beginning")) OnCommenceBeginning(originId);
    ImGui::SameLine();
    if (ImGui::Button("Mark Inception")) OnMarkInception(originId);
    ImGui::SameLine();
    if (ImGui::Button("Declare Originated")) OnDeclareOriginated(originId);
}

void PrimordialEssencePanel::RenderSourceAbsoluteDetails(const std::string& sourceId) {
    auto source = PrimordialEssence::PrimordialEssenceEngine::GetSourceAbsolute(sourceId);
    if (!source) return;
    
    ImGui::Separator();
    ImGui::Text("Details: %s", source->name.c_str());
    
    ImGui::Text("Source: %.2f", source->source);
    ImGui::ProgressBar(source->source);
    
    ImGui::Text("Wellspring: %.2f", source->wellspring);
    ImGui::ProgressBar(source->wellspring);
    
    ImGui::Text("Fountain: %.2f", source->fountain);
    ImGui::ProgressBar(source->fountain);
    
    if (ImGui::Button("Open Wellspring")) OnOpenWellspring(sourceId);
    ImGui::SameLine();
    if (ImGui::Button("Activate Fountain")) OnActivateFountain(sourceId);
    ImGui::SameLine();
    if (ImGui::Button("Declare Sourced")) OnDeclareSourced(sourceId);
}

void PrimordialEssencePanel::RenderRootAbsoluteDetails(const std::string& rootId) {
    auto root = PrimordialEssence::PrimordialEssenceEngine::GetRootAbsolute(rootId);
    if (!root) return;
    
    ImGui::Separator();
    ImGui::Text("Details: %s", root->name.c_str());
    
    ImGui::Text("Root: %.2f", root->root);
    ImGui::ProgressBar(root->root);
    
    ImGui::Text("Basis: %.2f", root->basis);
    ImGui::ProgressBar(root->basis);
    
    ImGui::Text("Core: %.2f", root->core);
    ImGui::ProgressBar(root->core);
    
    if (ImGui::Button("Strengthen Basis")) OnStrengthenBasis(rootId);
    ImGui::SameLine();
    if (ImGui::Button("Fortify Core")) OnFortifyCore(rootId);
    ImGui::SameLine();
    if (ImGui::Button("Declare Rooted")) OnDeclareRooted(rootId);
}

void PrimordialEssencePanel::RenderFoundationAbsoluteDetails(const std::string& foundationId) {
    auto foundation = PrimordialEssence::PrimordialEssenceEngine::GetFoundationAbsolute(foundationId);
    if (!foundation) return;
    
    ImGui::Separator();
    ImGui::Text("Details: %s", foundation->name.c_str());
    
    ImGui::Text("Foundation: %.2f", foundation->foundation);
    ImGui::ProgressBar(foundation->foundation);
    
    ImGui::Text("Groundwork: %.2f", foundation->groundwork);
    ImGui::ProgressBar(foundation->groundwork);
    
    ImGui::Text("Underpinning: %.2f", foundation->underpinning);
    ImGui::ProgressBar(foundation->underpinning);
    
    if (ImGui::Button("Prepare Groundwork")) OnPrepareGroundwork(foundationId);
    ImGui::SameLine();
    if (ImGui::Button("Secure Underpinning")) OnSecureUnderpinning(foundationId);
    ImGui::SameLine();
    if (ImGui::Button("Declare Founded")) OnDeclareFounded(foundationId);
}

void PrimordialEssencePanel::RenderGroundAbsoluteDetails(const std::string& groundId) {
    auto ground = PrimordialEssence::PrimordialEssenceEngine::GetGroundAbsolute(groundId);
    if (!ground) return;
    
    ImGui::Separator();
    ImGui::Text("Details: %s", ground->name.c_str());
    
    ImGui::Text("Ground: %.2f", ground->ground);
    ImGui::ProgressBar(ground->ground);
    
    ImGui::Text("Soil: %.2f", ground->soil);
    ImGui::ProgressBar(ground->soil);
    
    ImGui::Text("Bedrock: %.2f", ground->bedrock);
    ImGui::ProgressBar(ground->bedrock);
    
    if (ImGui::Button("Cultivate Soil")) OnCultivateSoil(groundId);
    ImGui::SameLine();
    if (ImGui::Button("Expose Bedrock")) OnExposeBedrock(groundId);
    ImGui::SameLine();
    if (ImGui::Button("Declare Grounded")) OnDeclareGrounded(groundId);
}

void PrimordialEssencePanel::SelectPrimordialStructure(const std::string& primordialId) {
    m_selectedPrimordialId = primordialId;
}

void PrimordialEssencePanel::SelectOriginAbsolute(const std::string& originId) {
    m_selectedOriginId = originId;
}

void PrimordialEssencePanel::SelectSourceAbsolute(const std::string& sourceId) {
    m_selectedSourceId = sourceId;
}

void PrimordialEssencePanel::SelectRootAbsolute(const std::string& rootId) {
    m_selectedRootId = rootId;
}

void PrimordialEssencePanel::SelectFoundationAbsolute(const std::string& foundationId) {
    m_selectedFoundationId = foundationId;
}

void PrimordialEssencePanel::SelectGroundAbsolute(const std::string& groundId) {
    m_selectedGroundId = groundId;
}

void PrimordialEssencePanel::CreateNewPrimordialStructure() {
    ImGui::OpenPopup("Create Primordial Structure");
}

void PrimordialEssencePanel::CreateNewOriginAbsolute() {
    PrimordialEssence::PrimordialEssenceEngine::CreateOriginAbsolute("New Origin Absolute");
}

void PrimordialEssencePanel::CreateNewSourceAbsolute() {
    PrimordialEssence::PrimordialEssenceEngine::CreateSourceAbsolute("New Source Absolute");
}

void PrimordialEssencePanel::CreateNewRootAbsolute() {
    PrimordialEssence::PrimordialEssenceEngine::CreateRootAbsolute("New Root Absolute");
}

void PrimordialEssencePanel::CreateNewFoundationAbsolute() {
    PrimordialEssence::PrimordialEssenceEngine::CreateFoundationAbsolute("New Foundation Absolute");
}

void PrimordialEssencePanel::CreateNewGroundAbsolute() {
    PrimordialEssence::PrimordialEssenceEngine::CreateGroundAbsolute("New Ground Absolute");
}

void PrimordialEssencePanel::ClearInputBuffers() {
    memset(m_newPrimordialName, 0, sizeof(m_newPrimordialName));
    memset(m_newOriginName, 0, sizeof(m_newOriginName));
    memset(m_newSourceName, 0, sizeof(m_newSourceName));
    memset(m_newRootName, 0, sizeof(m_newRootName));
    memset(m_newFoundationName, 0, sizeof(m_newFoundationName));
    memset(m_newGroundName, 0, sizeof(m_newGroundName));
}

bool PrimordialEssencePanel::FilterMatches(const std::string& text) const {
    if (strlen(m_filterBuffer) == 0) return true;
    return text.find(m_filterBuffer) != std::string::npos;
}

// Action handlers
void PrimordialEssencePanel::OnDeepenPrimordiality(const std::string& primordialId) {
    PrimordialEssence::PrimordialEssenceEngine::DeepenPrimordiality(primordialId, 0.1f);
}

void PrimordialEssencePanel::OnTraceOrigin(const std::string& primordialId) {
    PrimordialEssence::PrimordialEssenceEngine::TraceOrigin(primordialId, 0.1f);
}

void PrimordialEssencePanel::OnTapSource(const std::string& primordialId) {
    PrimordialEssence::PrimordialEssenceEngine::TapSource(primordialId, 0.1f);
}

void PrimordialEssencePanel::OnExtendRoot(const std::string& primordialId) {
    PrimordialEssence::PrimordialEssenceEngine::ExtendRoot(primordialId, 0.1f);
}

void PrimordialEssencePanel::OnLayFoundation(const std::string& primordialId) {
    PrimordialEssence::PrimordialEssenceEngine::LayFoundation(primordialId, 0.1f);
}

void PrimordialEssencePanel::OnEstablishGround(const std::string& primordialId) {
    PrimordialEssence::PrimordialEssenceEngine::EstablishGround(primordialId, 0.1f);
}

void PrimordialEssencePanel::OnCommenceBeginning(const std::string& originId) {
    PrimordialEssence::PrimordialEssenceEngine::CommenceBeginning(originId, 0.1f);
}

void PrimordialEssencePanel::OnMarkInception(const std::string& originId) {
    PrimordialEssence::PrimordialEssenceEngine::MarkInception(originId, 0.1f);
}

void PrimordialEssencePanel::OnDeclareOriginated(const std::string& originId) {
    PrimordialEssence::PrimordialEssenceEngine::DeclareOriginated(originId);
}

void PrimordialEssencePanel::OnOpenWellspring(const std::string& sourceId) {
    PrimordialEssence::PrimordialEssenceEngine::OpenWellspring(sourceId, 0.1f);
}

void PrimordialEssencePanel::OnActivateFountain(const std::string& sourceId) {
    PrimordialEssence::PrimordialEssenceEngine::ActivateFountain(sourceId, 0.1f);
}

void PrimordialEssencePanel::OnDeclareSourced(const std::string& sourceId) {
    PrimordialEssence::PrimordialEssenceEngine::DeclareSourced(sourceId);
}

void PrimordialEssencePanel::OnStrengthenBasis(const std::string& rootId) {
    PrimordialEssence::PrimordialEssenceEngine::StrengthenBasis(rootId, 0.1f);
}

void PrimordialEssencePanel::OnFortifyCore(const std::string& rootId) {
    PrimordialEssence::PrimordialEssenceEngine::FortifyCore(rootId, 0.1f);
}

void PrimordialEssencePanel::OnDeclareRooted(const std::string& rootId) {
    PrimordialEssence::PrimordialEssenceEngine::DeclareRooted(rootId);
}

void PrimordialEssencePanel::OnPrepareGroundwork(const std::string& foundationId) {
    PrimordialEssence::PrimordialEssenceEngine::PrepareGroundwork(foundationId, 0.1f);
}

void PrimordialEssencePanel::OnSecureUnderpinning(const std::string& foundationId) {
    PrimordialEssence::PrimordialEssenceEngine::SecureUnderpinning(foundationId, 0.1f);
}

void PrimordialEssencePanel::OnDeclareFounded(const std::string& foundationId) {
    PrimordialEssence::PrimordialEssenceEngine::DeclareFounded(foundationId);
}

void PrimordialEssencePanel::OnCultivateSoil(const std::string& groundId) {
    PrimordialEssence::PrimordialEssenceEngine::CultivateSoil(groundId, 0.1f);
}

void PrimordialEssencePanel::OnExposeBedrock(const std::string& groundId) {
    PrimordialEssence::PrimordialEssenceEngine::ExposeBedrock(groundId, 0.1f);
}

void PrimordialEssencePanel::OnDeclareGrounded(const std::string& groundId) {
    PrimordialEssence::PrimordialEssenceEngine::DeclareGrounded(groundId);
}

} // namespace IDE
