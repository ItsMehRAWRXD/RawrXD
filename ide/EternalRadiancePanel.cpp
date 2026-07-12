#include "EternalRadiancePanel.hpp"
#include "../infinite/EternalRadianceEngine.hpp"
#include "../infinite/EternalRadianceLoop.hpp"
#include <imgui.h>
#include <cstring>
#include <iomanip>
#include <sstream>

namespace IDE {

EternalRadiancePanel::EternalRadiancePanel()
    : m_initialized(false)
    , m_visible(false)
    , m_currentTab(0)
{
    ClearInputBuffers();
    std::memset(m_filterBuffer, 0, sizeof(m_filterBuffer));
}

EternalRadiancePanel::~EternalRadiancePanel() {
    Shutdown();
}

bool EternalRadiancePanel::Initialize() {
    if (m_initialized) return true;
    
    // Initialize Eternal Radiance engine
    if (!EternalRadiance::EternalRadianceEngine::Initialize()) {
        return false;
    }
    
    // Initialize Eternal Radiance loop
    EternalRadiance::EternalRadianceLoopConfig loopConfig;
    loopConfig.targetTPS = 60;
    loopConfig.maxFPS = 60;
    loopConfig.enableFrameLimiting = true;
    loopConfig.enableMetrics = true;
    
    if (!EternalRadiance::EternalRadianceLoop::Init(loopConfig)) {
        return false;
    }
    
    m_initialized = true;
    return true;
}

void EternalRadiancePanel::Shutdown() {
    if (!m_initialized) return;
    
    EternalRadiance::EternalRadianceLoop::Shutdown();
    EternalRadiance::EternalRadianceEngine::Shutdown();
    
    m_initialized = false;
}

bool EternalRadiancePanel::IsInitialized() const {
    return m_initialized;
}

void EternalRadiancePanel::Show() {
    m_visible = true;
}

void EternalRadiancePanel::Hide() {
    m_visible = false;
}

void EternalRadiancePanel::ToggleVisibility() {
    m_visible = !m_visible;
}

bool EternalRadiancePanel::IsVisible() const {
    return m_visible;
}

void EternalRadiancePanel::Render() {
    if (!m_visible || !m_initialized) return;
    
    RenderWindow();
}

void EternalRadiancePanel::RenderWindow() {
    ImGui::SetNextWindowSize(ImVec2(900, 700), ImGuiCond_FirstUseEver);
    
    if (ImGui::Begin("Eternal Radiance (Layer 115)", &m_visible)) {
        RenderTabBar();
        
        switch (static_cast<Tab>(m_currentTab)) {
            case Tab::EternalStructures:
                RenderEternalStructuresTab();
                break;
            case Tab::GlowEternals:
                RenderGlowEternalsTab();
                break;
            case Tab::ShineEternals:
                RenderShineEternalsTab();
                break;
            case Tab::BrightnessEternals:
                RenderBrightnessEternalsTab();
                break;
            case Tab::IntensityEternals:
                RenderIntensityEternalsTab();
                break;
            case Tab::LuminescenceEternals:
                RenderLuminescenceEternalsTab();
                break;
            case Tab::TransparencyEternals:
                RenderTransparencyEternalsTab();
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

void EternalRadiancePanel::RenderTabBar() {
    if (ImGui::BeginTabBar("EternalRadianceTabs")) {
        if (ImGui::BeginTabItem("Eternal Structures")) {
            m_currentTab = static_cast<int>(Tab::EternalStructures);
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("Glow Eternals")) {
            m_currentTab = static_cast<int>(Tab::GlowEternals);
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("Shine Eternals")) {
            m_currentTab = static_cast<int>(Tab::ShineEternals);
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("Brightness Eternals")) {
            m_currentTab = static_cast<int>(Tab::BrightnessEternals);
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("Intensity Eternals")) {
            m_currentTab = static_cast<int>(Tab::IntensityEternals);
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("Luminescence Eternals")) {
            m_currentTab = static_cast<int>(Tab::LuminescenceEternals);
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("Transparency Eternals")) {
            m_currentTab = static_cast<int>(Tab::TransparencyEternals);
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

void EternalRadiancePanel::RenderEternalStructuresTab() {
    ImGui::Text("Eternal Radiance Structures");
    ImGui::Separator();
    
    // Filter
    ImGui::InputText("Filter", m_filterBuffer, sizeof(m_filterBuffer));
    ImGui::SameLine();
    if (ImGui::Button("Clear")) {
        std::memset(m_filterBuffer, 0, sizeof(m_filterBuffer));
    }
    
    ImGui::Spacing();
    
    // Create new
    ImGui::InputText("New Name", m_newEternalName, sizeof(m_newEternalName));
    ImGui::SameLine();
    if (ImGui::Button("Create")) {
        CreateNewEternalRadianceStructure();
    }
    
    ImGui::Spacing();
    ImGui::Separator();
    
    // List
    auto eternalIds = EternalRadiance::EternalRadianceEngine::GetAllEternalRadianceStructureIds();
    
    ImGui::BeginChild("EternalList", ImVec2(300, 0), true);
    for (const auto& id : eternalIds) {
        auto eternal = EternalRadiance::EternalRadianceEngine::GetEternalRadianceStructure(id);
        if (eternal && FilterMatches(eternal->name)) {
            bool isSelected = (m_selectedEternalId == id);
            if (ImGui::Selectable(eternal->name.c_str(), isSelected)) {
                SelectEternalRadianceStructure(id);
            }
        }
    }
    ImGui::EndChild();
    
    ImGui::SameLine();
    
    // Details
    ImGui::BeginChild("EternalDetails", ImVec2(0, 0), true);
    if (!m_selectedEternalId.empty()) {
        RenderEternalRadianceStructureDetails(m_selectedEternalId);
    } else {
        ImGui::Text("Select an eternal radiance structure to view details");
    }
    ImGui::EndChild();
}

void EternalRadiancePanel::RenderGlowEternalsTab() {
    ImGui::Text("Glow Eternals");
    ImGui::Separator();
    
    ImGui::InputText("Filter##Glow", m_filterBuffer, sizeof(m_filterBuffer));
    ImGui::SameLine();
    if (ImGui::Button("Clear##Glow")) {
        std::memset(m_filterBuffer, 0, sizeof(m_filterBuffer));
    }
    
    ImGui::Spacing();
    
    ImGui::InputText("New Name##Glow", m_newGlowName, sizeof(m_newGlowName));
    ImGui::SameLine();
    if (ImGui::Button("Create##Glow")) {
        CreateNewGlowEternal();
    }
    
    ImGui::Spacing();
    ImGui::Separator();
    
    auto glowIds = EternalRadiance::EternalRadianceEngine::GetAllGlowEternalIds();
    
    ImGui::BeginChild("GlowList", ImVec2(300, 0), true);
    for (const auto& id : glowIds) {
        auto glow = EternalRadiance::EternalRadianceEngine::GetGlowEternal(id);
        if (glow && FilterMatches(glow->name)) {
            bool isSelected = (m_selectedGlowId == id);
            if (ImGui::Selectable(glow->name.c_str(), isSelected)) {
                SelectGlowEternal(id);
            }
        }
    }
    ImGui::EndChild();
    
    ImGui::SameLine();
    
    ImGui::BeginChild("GlowDetails", ImVec2(0, 0), true);
    if (!m_selectedGlowId.empty()) {
        RenderGlowEternalDetails(m_selectedGlowId);
    } else {
        ImGui::Text("Select a glow eternal to view details");
    }
    ImGui::EndChild();
}

void EternalRadiancePanel::RenderShineEternalsTab() {
    ImGui::Text("Shine Eternals");
    ImGui::Separator();
    
    ImGui::InputText("Filter##Shine", m_filterBuffer, sizeof(m_filterBuffer));
    ImGui::SameLine();
    if (ImGui::Button("Clear##Shine")) {
        std::memset(m_filterBuffer, 0, sizeof(m_filterBuffer));
    }
    
    ImGui::Spacing();
    
    ImGui::InputText("New Name##Shine", m_newShineName, sizeof(m_newShineName));
    ImGui::SameLine();
    if (ImGui::Button("Create##Shine")) {
        CreateNewShineEternal();
    }
    
    ImGui::Spacing();
    ImGui::Separator();
    
    auto shineIds = EternalRadiance::EternalRadianceEngine::GetAllShineEternalIds();
    
    ImGui::BeginChild("ShineList", ImVec2(300, 0), true);
    for (const auto& id : shineIds) {
        auto shine = EternalRadiance::EternalRadianceEngine::GetShineEternal(id);
        if (shine && FilterMatches(shine->name)) {
            bool isSelected = (m_selectedShineId == id);
            if (ImGui::Selectable(shine->name.c_str(), isSelected)) {
                SelectShineEternal(id);
            }
        }
    }
    ImGui::EndChild();
    
    ImGui::SameLine();
    
    ImGui::BeginChild("ShineDetails", ImVec2(0, 0), true);
    if (!m_selectedShineId.empty()) {
        RenderShineEternalDetails(m_selectedShineId);
    } else {
        ImGui::Text("Select a shine eternal to view details");
    }
    ImGui::EndChild();
}

void EternalRadiancePanel::RenderBrightnessEternalsTab() {
    ImGui::Text("Brightness Eternals");
    ImGui::Separator();
    
    ImGui::InputText("Filter##Brightness", m_filterBuffer, sizeof(m_filterBuffer));
    ImGui::SameLine();
    if (ImGui::Button("Clear##Brightness")) {
        std::memset(m_filterBuffer, 0, sizeof(m_filterBuffer));
    }
    
    ImGui::Spacing();
    
    ImGui::InputText("New Name##Brightness", m_newBrightnessName, sizeof(m_newBrightnessName));
    ImGui::SameLine();
    if (ImGui::Button("Create##Brightness")) {
        CreateNewBrightnessEternal();
    }
    
    ImGui::Spacing();
    ImGui::Separator();
    
    auto brightnessIds = EternalRadiance::EternalRadianceEngine::GetAllBrightnessEternalIds();
    
    ImGui::BeginChild("BrightnessList", ImVec2(300, 0), true);
    for (const auto& id : brightnessIds) {
        auto brightness = EternalRadiance::EternalRadianceEngine::GetBrightnessEternal(id);
        if (brightness && FilterMatches(brightness->name)) {
            bool isSelected = (m_selectedBrightnessId == id);
            if (ImGui::Selectable(brightness->name.c_str(), isSelected)) {
                SelectBrightnessEternal(id);
            }
        }
    }
    ImGui::EndChild();
    
    ImGui::SameLine();
    
    ImGui::BeginChild("BrightnessDetails", ImVec2(0, 0), true);
    if (!m_selectedBrightnessId.empty()) {
        RenderBrightnessEternalDetails(m_selectedBrightnessId);
    } else {
        ImGui::Text("Select a brightness eternal to view details");
    }
    ImGui::EndChild();
}

void EternalRadiancePanel::RenderIntensityEternalsTab() {
    ImGui::Text("Intensity Eternals");
    ImGui::Separator();
    
    ImGui::InputText("Filter##Intensity", m_filterBuffer, sizeof(m_filterBuffer));
    ImGui::SameLine();
    if (ImGui::Button("Clear##Intensity")) {
        std::memset(m_filterBuffer, 0, sizeof(m_filterBuffer));
    }
    
    ImGui::Spacing();
    
    ImGui::InputText("New Name##Intensity", m_newIntensityName, sizeof(m_newIntensityName));
    ImGui::SameLine();
    if (ImGui::Button("Create##Intensity")) {
        CreateNewIntensityEternal();
    }
    
    ImGui::Spacing();
    ImGui::Separator();
    
    auto intensityIds = EternalRadiance::EternalRadianceEngine::GetAllIntensityEternalIds();
    
    ImGui::BeginChild("IntensityList", ImVec2(300, 0), true);
    for (const auto& id : intensityIds) {
        auto intensity = EternalRadiance::EternalRadianceEngine::GetIntensityEternal(id);
        if (intensity && FilterMatches(intensity->name)) {
            bool isSelected = (m_selectedIntensityId == id);
            if (ImGui::Selectable(intensity->name.c_str(), isSelected)) {
                SelectIntensityEternal(id);
            }
        }
    }
    ImGui::EndChild();
    
    ImGui::SameLine();
    
    ImGui::BeginChild("IntensityDetails", ImVec2(0, 0), true);
    if (!m_selectedIntensityId.empty()) {
        RenderIntensityEternalDetails(m_selectedIntensityId);
    } else {
        ImGui::Text("Select an intensity eternal to view details");
    }
    ImGui::EndChild();
}

void EternalRadiancePanel::RenderLuminescenceEternalsTab() {
    ImGui::Text("Luminescence Eternals");
    ImGui::Separator();
    
    ImGui::InputText("Filter##Luminescence", m_filterBuffer, sizeof(m_filterBuffer));
    ImGui::SameLine();
    if (ImGui::Button("Clear##Luminescence")) {
        std::memset(m_filterBuffer, 0, sizeof(m_filterBuffer));
    }
    
    ImGui::Spacing();
    
    ImGui::InputText("New Name##Luminescence", m_newLuminescenceName, sizeof(m_newLuminescenceName));
    ImGui::SameLine();
    if (ImGui::Button("Create##Luminescence")) {
        CreateNewLuminescenceEternal();
    }
    
    ImGui::Spacing();
    ImGui::Separator();
    
    auto luminescenceIds = EternalRadiance::EternalRadianceEngine::GetAllLuminescenceEternalIds();
    
    ImGui::BeginChild("LuminescenceList", ImVec2(300, 0), true);
    for (const auto& id : luminescenceIds) {
        auto luminescence = EternalRadiance::EternalRadianceEngine::GetLuminescenceEternal(id);
        if (luminescence && FilterMatches(luminescence->name)) {
            bool isSelected = (m_selectedLuminescenceId == id);
            if (ImGui::Selectable(luminescence->name.c_str(), isSelected)) {
                SelectLuminescenceEternal(id);
            }
        }
    }
    ImGui::EndChild();
    
    ImGui::SameLine();
    
    ImGui::BeginChild("LuminescenceDetails", ImVec2(0, 0), true);
    if (!m_selectedLuminescenceId.empty()) {
        RenderLuminescenceEternalDetails(m_selectedLuminescenceId);
    } else {
        ImGui::Text("Select a luminescence eternal to view details");
    }
    ImGui::EndChild();
}

void EternalRadiancePanel::RenderTransparencyEternalsTab() {
    ImGui::Text("Transparency Eternals");
    ImGui::Separator();
    
    ImGui::InputText("Filter##Transparency", m_filterBuffer, sizeof(m_filterBuffer));
    ImGui::SameLine();
    if (ImGui::Button("Clear##Transparency")) {
        std::memset(m_filterBuffer, 0, sizeof(m_filterBuffer));
    }
    
    ImGui::Spacing();
    
    ImGui::InputText("New Name##Transparency", m_newTransparencyName, sizeof(m_newTransparencyName));
    ImGui::SameLine();
    if (ImGui::Button("Create##Transparency")) {
        CreateNewTransparencyEternal();
    }
    
    ImGui::Spacing();
    ImGui::Separator();
    
    auto transparencyIds = EternalRadiance::EternalRadianceEngine::GetAllTransparencyEternalIds();
    
    ImGui::BeginChild("TransparencyList", ImVec2(300, 0), true);
    for (const auto& id : transparencyIds) {
        auto transparency = EternalRadiance::EternalRadianceEngine::GetTransparencyEternal(id);
        if (transparency && FilterMatches(transparency->name)) {
            bool isSelected = (m_selectedTransparencyId == id);
            if (ImGui::Selectable(transparency->name.c_str(), isSelected)) {
                SelectTransparencyEternal(id);
            }
        }
    }
    ImGui::EndChild();
    
    ImGui::SameLine();
    
    ImGui::BeginChild("TransparencyDetails", ImVec2(0, 0), true);
    if (!m_selectedTransparencyId.empty()) {
        RenderTransparencyEternalDetails(m_selectedTransparencyId);
    } else {
        ImGui::Text("Select a transparency eternal to view details");
    }
    ImGui::EndChild();
}

void EternalRadiancePanel::RenderMetricsTab() {
    ImGui::Text("Eternal Radiance Metrics");
    ImGui::Separator();
    
    auto metrics = EternalRadiance::EternalRadianceLoop::GetMetrics();
    
    ImGui::Text("Performance Metrics:");
    DrawMetric("Current TPS", metrics.currentTPS, "%.1f");
    DrawMetric("Current FPS", metrics.currentFPS, "%.1f");
    DrawMetric("Average Tick Time (ms)", metrics.averageTickTimeMs, "%.3f");
    DrawMetric("Average Frame Time (ms)", metrics.averageFrameTimeMs, "%.3f");
    
    ImGui::Spacing();
    ImGui::Separator();
    
    ImGui::Text("Counters:");
    ImGui::Text("Total Ticks: %lld", metrics.totalTicks);
    ImGui::Text("Total Frames: %lld", metrics.totalFrames);
    
    ImGui::Spacing();
    ImGui::Separator();
    
    ImGui::Text("Engine Statistics:");
    ImGui::Text("Eternal Structures: %zu", EternalRadiance::EternalRadianceEngine::GetAllEternalRadianceStructureIds().size());
    ImGui::Text("Glow Eternals: %zu", EternalRadiance::EternalRadianceEngine::GetAllGlowEternalIds().size());
    ImGui::Text("Shine Eternals: %zu", EternalRadiance::EternalRadianceEngine::GetAllShineEternalIds().size());
    ImGui::Text("Brightness Eternals: %zu", EternalRadiance::EternalRadianceEngine::GetAllBrightnessEternalIds().size());
    ImGui::Text("Intensity Eternals: %zu", EternalRadiance::EternalRadianceEngine::GetAllIntensityEternalIds().size());
    ImGui::Text("Luminescence Eternals: %zu", EternalRadiance::EternalRadianceEngine::GetAllLuminescenceEternalIds().size());
    ImGui::Text("Transparency Eternals: %zu", EternalRadiance::EternalRadianceEngine::GetAllTransparencyEternalIds().size());
}

void EternalRadiancePanel::RenderSettingsTab() {
    ImGui::Text("Eternal Radiance Settings");
    ImGui::Separator();
    
    auto config = EternalRadiance::EternalRadianceLoop::GetConfig();
    
    bool changed = false;
    
    changed |= ImGui::InputInt("Target TPS", &config.targetTPS);
    changed |= ImGui::InputInt("Max FPS", &config.maxFPS);
    changed |= ImGui::Checkbox("Enable Frame Limiting", &config.enableFrameLimiting);
    changed |= ImGui::Checkbox("Enable Metrics", &config.enableMetrics);
    
    if (changed) {
        EternalRadiance::EternalRadianceLoop::SetConfig(config);
    }
    
    ImGui::Spacing();
    ImGui::Separator();
    
    ImGui::Text("Loop Control:");
    
    if (EternalRadiance::EternalRadianceLoop::IsRunning()) {
        if (ImGui::Button("Stop Loop")) {
            EternalRadiance::EternalRadianceLoop::Stop();
        }
        ImGui::SameLine();
        if (EternalRadiance::EternalRadianceLoop::IsPaused()) {
            if (ImGui::Button("Resume")) {
                EternalRadiance::EternalRadianceLoop::Resume();
            }
        } else {
            if (ImGui::Button("Pause")) {
                EternalRadiance::EternalRadianceLoop::Pause();
            }
        }
    } else {
        if (ImGui::Button("Start Loop")) {
            EternalRadiance::EternalRadianceLoop::Start();
        }
    }
}

void EternalRadiancePanel::RenderEternalRadianceStructureDetails(const std::string& eternalId) {
    auto eternal = EternalRadiance::EternalRadianceEngine::GetEternalRadianceStructure(eternalId);
    if (!eternal) return;
    
    ImGui::Text("Name: %s", eternal->name.c_str());
    ImGui::Text("ID: %s", eternal->id.c_str());
    ImGui::Text("Created: %s", eternal->createdAt.c_str());
    ImGui::Text("Modified: %s", eternal->modifiedAt.c_str());
    
    ImGui::Spacing();
    ImGui::Separator();
    
    ImGui::Text("Properties:");
    DrawMetric("Glow", eternal->glow);
    DrawMetric("Shine", eternal->shine);
    DrawMetric("Brightness", eternal->brightness);
    DrawMetric("Intensity", eternal->intensity);
    DrawMetric("Luminescence", eternal->luminescence);
    DrawMetric("Transparency", eternal->transparency);
    
    ImGui::Spacing();
    ImGui::Separator();
    
    ImGui::Text("Actions:");
    if (ImGui::Button("Expand Eternal Radiance")) {
        OnExpandEternalRadiance(eternalId);
    }
    if (ImGui::Button("Amplify Glow")) {
        OnAmplifyGlow(eternalId);
    }
    if (ImGui::Button("Increase Shine")) {
        OnIncreaseShine(eternalId);
    }
    if (ImGui::Button("Enhance Brightness")) {
        OnEnhanceBrightness(eternalId);
    }
    if (ImGui::Button("Intensify Radiance")) {
        OnIntensifyRadiance(eternalId);
    }
    if (ImGui::Button("Spread Luminescence")) {
        OnSpreadLuminescence(eternalId);
    }
    if (ImGui::Button("Clarify Transparency")) {
        OnClarifyTransparency(eternalId);
    }
}

void EternalRadiancePanel::RenderGlowEternalDetails(const std::string& glowId) {
    auto glow = EternalRadiance::EternalRadianceEngine::GetGlowEternal(glowId);
    if (!glow) return;
    
    ImGui::Text("Name: %s", glow->name.c_str());
    ImGui::Text("ID: %s", glow->id.c_str());
    ImGui::Text("Is Eternal: %s", glow->isEternal ? "Yes" : "No");
    
    ImGui::Spacing();
    ImGui::Separator();
    
    ImGui::Text("Properties:");
    DrawMetric("Glow", glow->glow);
    DrawMetric("Shine", glow->shine);
    DrawMetric("Brightness", glow->brightness);
    DrawMetric("Intensity", glow->intensity);
    DrawMetric("Luminescence", glow->luminescence);
    DrawMetric("Transparency", glow->transparency);
    
    ImGui::Spacing();
    ImGui::Separator();
    
    ImGui::Text("Actions:");
    if (ImGui::Button("Intensify Glow Eternal")) {
        OnIntensifyGlowEternal(glowId);
    }
    if (ImGui::Button("Amplify Shine Eternal")) {
        OnAmplifyShineEternal(glowId);
    }
    if (ImGui::Button("Declare Glow Eternal")) {
        OnDeclareGlowEternal(glowId);
    }
}

void EternalRadiancePanel::RenderShineEternalDetails(const std::string& shineId) {
    auto shine = EternalRadiance::EternalRadianceEngine::GetShineEternal(shineId);
    if (!shine) return;
    
    ImGui::Text("Name: %s", shine->name.c_str());
    ImGui::Text("ID: %s", shine->id.c_str());
    ImGui::Text("Is Eternal: %s", shine->isEternal ? "Yes" : "No");
    
    ImGui::Spacing();
    ImGui::Separator();
    
    ImGui::Text("Properties:");
    DrawMetric("Glow", shine->glow);
    DrawMetric("Shine", shine->shine);
    DrawMetric("Brightness", shine->brightness);
    DrawMetric("Intensity", shine->intensity);
    DrawMetric("Luminescence", shine->luminescence);
    DrawMetric("Transparency", shine->transparency);
    
    ImGui::Spacing();
    ImGui::Separator();
    
    ImGui::Text("Actions:");
    if (ImGui::Button("Increase Brightness Eternal")) {
        OnIncreaseBrightnessEternal(shineId);
    }
    if (ImGui::Button("Intensify Shine Eternal")) {
        OnIntensifyShineEternal(shineId);
    }
    if (ImGui::Button("Declare Shine Eternal")) {
        OnDeclareShineEternal(shineId);
    }
}

void EternalRadiancePanel::RenderBrightnessEternalDetails(const std::string& brightnessId) {
    auto brightness = EternalRadiance::EternalRadianceEngine::GetBrightnessEternal(brightnessId);
    if (!brightness) return;
    
    ImGui::Text("Name: %s", brightness->name.c_str());
    ImGui::Text("ID: %s", brightness->id.c_str());
    ImGui::Text("Is Eternal: %s", brightness->isEternal ? "Yes" : "No");
    
    ImGui::Spacing();
    ImGui::Separator();
    
    ImGui::Text("Properties:");
    DrawMetric("Glow", brightness->glow);
    DrawMetric("Shine", brightness->shine);
    DrawMetric("Brightness", brightness->brightness);
    DrawMetric("Intensity", brightness->intensity);
    DrawMetric("Luminescence", brightness->luminescence);
    DrawMetric("Transparency", brightness->transparency);
    
    ImGui::Spacing();
    ImGui::Separator();
    
    ImGui::Text("Actions:");
    if (ImGui::Button("Brighten Eternal")) {
        OnBrightenEternal(brightnessId);
    }
    if (ImGui::Button("Polish Eternal")) {
        OnPolishEternal(brightnessId);
    }
    if (ImGui::Button("Declare Brightness Eternal")) {
        OnDeclareBrightnessEternal(brightnessId);
    }
}

void EternalRadiancePanel::RenderIntensityEternalDetails(const std::string& intensityId) {
    auto intensity = EternalRadiance::EternalRadianceEngine::GetIntensityEternal(intensityId);
    if (!intensity) return;
    
    ImGui::Text("Name: %s", intensity->name.c_str());
    ImGui::Text("ID: %s", intensity->id.c_str());
    ImGui::Text("Is Eternal: %s", intensity->isEternal ? "Yes" : "No");
    
    ImGui::Spacing();
    ImGui::Separator();
    
    ImGui::Text("Properties:");
    DrawMetric("Glow", intensity->glow);
    DrawMetric("Shine", intensity->shine);
    DrawMetric("Brightness", intensity->brightness);
    DrawMetric("Intensity", intensity->intensity);
    DrawMetric("Luminescence", intensity->luminescence);
    DrawMetric("Transparency", intensity->transparency);
    
    ImGui::Spacing();
    ImGui::Separator();
    
    ImGui::Text("Actions:");
    if (ImGui::Button("Strengthen Eternal")) {
        OnStrengthenEternal(intensityId);
    }
    if (ImGui::Button("Deepen Eternal")) {
        OnDeepenEternal(intensityId);
    }
    if (ImGui::Button("Declare Intensity Eternal")) {
        OnDeclareIntensityEternal(intensityId);
    }
}

void EternalRadiancePanel::RenderLuminescenceEternalDetails(const std::string& luminescenceId) {
    auto luminescence = EternalRadiance::EternalRadianceEngine::GetLuminescenceEternal(luminescenceId);
    if (!luminescence) return;
    
    ImGui::Text("Name: %s", luminescence->name.c_str());
    ImGui::Text("ID: %s", luminescence->id.c_str());
    ImGui::Text("Is Eternal: %s", luminescence->isEternal ? "Yes" : "No");
    
    ImGui::Spacing();
    ImGui::Separator();
    
    ImGui::Text("Properties:");
    DrawMetric("Glow", luminescence->glow);
    DrawMetric("Shine", luminescence->shine);
    DrawMetric("Brightness", luminescence->brightness);
    DrawMetric("Intensity", luminescence->intensity);
    DrawMetric("Luminescence", luminescence->luminescence);
    DrawMetric("Transparency", luminescence->transparency);
    
    ImGui::Spacing();
    ImGui::Separator();
    
    ImGui::Text("Actions:");
    if (ImGui::Button("Illuminate Eternal")) {
        OnIlluminateEternal(luminescenceId);
    }
    if (ImGui::Button("Radiate Eternal")) {
        OnRadiateEternal(luminescenceId);
    }
    if (ImGui::Button("Declare Luminescence Eternal")) {
        OnDeclareLuminescenceEternal(luminescenceId);
    }
}

void EternalRadiancePanel::RenderTransparencyEternalDetails(const std::string& transparencyId) {
    auto transparency = EternalRadiance::EternalRadianceEngine::GetTransparencyEternal(transparencyId);
    if (!transparency) return;
    
    ImGui::Text("Name: %s", transparency->name.c_str());
    ImGui::Text("ID: %s", transparency->id.c_str());
    ImGui::Text("Is Eternal: %s", transparency->isEternal ? "Yes" : "No");
    
    ImGui::Spacing();
    ImGui::Separator();
    
    ImGui::Text("Properties:");
    DrawMetric("Glow", transparency->glow);
    DrawMetric("Shine", transparency->shine);
    DrawMetric("Brightness", transparency->brightness);
    DrawMetric("Intensity", transparency->intensity);
    DrawMetric("Luminescence", transparency->luminescence);
    DrawMetric("Transparency", transparency->transparency);
    
    ImGui::Spacing();
    ImGui::Separator();
    
    ImGui::Text("Actions:");
    if (ImGui::Button("Make Eternal Transparent")) {
        OnMakeEternalTransparent(transparencyId);
    }
    if (ImGui::Button("Increase Eternal Clarity")) {
        OnIncreaseEternalClarity(transparencyId);
    }
    if (ImGui::Button("Declare Transparency Eternal")) {
        OnDeclareTransparencyEternal(transparencyId);
    }
}

void EternalRadiancePanel::SelectEternalRadianceStructure(const std::string& eternalId) {
    m_selectedEternalId = eternalId;
}

void EternalRadiancePanel::SelectGlowEternal(const std::string& glowId) {
    m_selectedGlowId = glowId;
}

void EternalRadiancePanel::SelectShineEternal(const std::string& shineId) {
    m_selectedShineId = shineId;
}

void EternalRadiancePanel::SelectBrightnessEternal(const std::string& brightnessId) {
    m_selectedBrightnessId = brightnessId;
}

void EternalRadiancePanel::SelectIntensityEternal(const std::string& intensityId) {
    m_selectedIntensityId = intensityId;
}

void EternalRadiancePanel::SelectLuminescenceEternal(const std::string& luminescenceId) {
    m_selectedLuminescenceId = luminescenceId;
}

void EternalRadiancePanel::SelectTransparencyEternal(const std::string& transparencyId) {
    m_selectedTransparencyId = transparencyId;
}

void EternalRadiancePanel::CreateNewEternalRadianceStructure() {
    if (std::strlen(m_newEternalName) > 0) {
        EternalRadiance::EternalRadianceEngine::CreateEternalRadianceStructure(m_newEternalName);
        std::memset(m_newEternalName, 0, sizeof(m_newEternalName));
    }
}

void EternalRadiancePanel::CreateNewGlowEternal() {
    if (std::strlen(m_newGlowName) > 0) {
        EternalRadiance::EternalRadianceEngine::CreateGlowEternal(m_newGlowName);
        std::memset(m_newGlowName, 0, sizeof(m_newGlowName));
    }
}

void EternalRadiancePanel::CreateNewShineEternal() {
    if (std::strlen(m_newShineName) > 0) {
        EternalRadiance::EternalRadianceEngine::CreateShineEternal(m_newShineName);
        std::memset(m_newShineName, 0, sizeof(m_newShineName));
    }
}

void EternalRadiancePanel::CreateNewBrightnessEternal() {
    if (std::strlen(m_newBrightnessName) > 0) {
        EternalRadiance::EternalRadianceEngine::CreateBrightnessEternal(m_newBrightnessName);
        std::memset(m_newBrightnessName, 0, sizeof(m_newBrightnessName));
    }
}

void EternalRadiancePanel::CreateNewIntensityEternal() {
    if (std::strlen(m_newIntensityName) > 0) {
        EternalRadiance::EternalRadianceEngine::CreateIntensityEternal(m_newIntensityName);
        std::memset(m_newIntensityName, 0, sizeof(m_newIntensityName));
    }
}

void EternalRadiancePanel::CreateNewLuminescenceEternal() {
    if (std::strlen(m_newLuminescenceName) > 0) {
        EternalRadiance::EternalRadianceEngine::CreateLuminescenceEternal(m_newLuminescenceName);
        std::memset(m_newLuminescenceName, 0, sizeof(m_newLuminescenceName));
    }
}

void EternalRadiancePanel::CreateNewTransparencyEternal() {
    if (std::strlen(m_newTransparencyName) > 0) {
        EternalRadiance::EternalRadianceEngine::CreateTransparencyEternal(m_newTransparencyName);
        std::memset(m_newTransparencyName, 0, sizeof(m_newTransparencyName));
    }
}

void EternalRadiancePanel::ClearInputBuffers() {
    std::memset(m_newEternalName, 0, sizeof(m_newEternalName));
    std::memset(m_newGlowName, 0, sizeof(m_newGlowName));
    std::memset(m_newShineName, 0, sizeof(m_newShineName));
    std::memset(m_newBrightnessName, 0, sizeof(m_newBrightnessName));
    std::memset(m_newIntensityName, 0, sizeof(m_newIntensityName));
    std::memset(m_newLuminescenceName, 0, sizeof(m_newLuminescenceName));
    std::memset(m_newTransparencyName, 0, sizeof(m_newTransparencyName));
}

bool EternalRadiancePanel::FilterMatches(const std::string& text) const {
    if (std::strlen(m_filterBuffer) == 0) return true;
    return text.find(m_filterBuffer) != std::string::npos;
}

void EternalRadiancePanel::DrawProgressBar(float value, const ImVec4& color) {
    ImGui::PushStyleColor(ImGuiCol_PlotHistogram, color);
    ImGui::ProgressBar(value, ImVec2(-1, 0), "");
    ImGui::PopStyleColor();
}

void EternalRadiancePanel::DrawMetric(const char* label, float value, const char* format) {
    ImGui::Text("%s: ", label);
    ImGui::SameLine();
    ImGui::Text(format, value);
}

// Action handlers
void EternalRadiancePanel::OnExpandEternalRadiance(const std::string& eternalId) {
    EternalRadiance::EternalRadianceEngine::ExpandEternalRadiance(eternalId);
}

void EternalRadiancePanel::OnAmplifyGlow(const std::string& eternalId) {
    EternalRadiance::EternalRadianceEngine::AmplifyGlow(eternalId);
}

void EternalRadiancePanel::OnIncreaseShine(const std::string& eternalId) {
    EternalRadiance::EternalRadianceEngine::IncreaseShine(eternalId);
}

void EternalRadiancePanel::OnEnhanceBrightness(const std::string& eternalId) {
    EternalRadiance::EternalRadianceEngine::EnhanceBrightness(eternalId);
}

void EternalRadiancePanel::OnIntensifyRadiance(const std::string& eternalId) {
    EternalRadiance::EternalRadianceEngine::IntensifyRadiance(eternalId);
}

void EternalRadiancePanel::OnSpreadLuminescence(const std::string& eternalId) {
    EternalRadiance::EternalRadianceEngine::SpreadLuminescence(eternalId);
}

void EternalRadiancePanel::OnClarifyTransparency(const std::string& eternalId) {
    EternalRadiance::EternalRadianceEngine::ClarifyTransparency(eternalId);
}

void EternalRadiancePanel::OnIntensifyGlowEternal(const std::string& glowId) {
    EternalRadiance::EternalRadianceEngine::IntensifyGlowEternal(glowId);
}

void EternalRadiancePanel::OnAmplifyShineEternal(const std::string& glowId) {
    EternalRadiance::EternalRadianceEngine::AmplifyShineEternal(glowId);
}

void EternalRadiancePanel::OnDeclareGlowEternal(const std::string& glowId) {
    EternalRadiance::EternalRadianceEngine::DeclareGlowEternal(glowId);
}

void EternalRadiancePanel::OnIncreaseBrightnessEternal(const std::string& shineId) {
    EternalRadiance::EternalRadianceEngine::IncreaseBrightnessEternal(shineId);
}

void EternalRadiancePanel::OnIntensifyShineEternal(const std::string& shineId) {
    EternalRadiance::EternalRadianceEngine::IntensifyShineEternal(shineId);
}

void EternalRadiancePanel::OnDeclareShineEternal(const std::string& shineId) {
    EternalRadiance::EternalRadianceEngine::DeclareShineEternal(shineId);
}

void EternalRadiancePanel::OnBrightenEternal(const std::string& brightnessId) {
    EternalRadiance::EternalRadianceEngine::BrightenEternal(brightnessId);
}

void EternalRadiancePanel::OnPolishEternal(const std::string& brightnessId) {
    EternalRadiance::EternalRadianceEngine::PolishEternal(brightnessId);
}

void EternalRadiancePanel::OnDeclareBrightnessEternal(const std::string& brightnessId) {
    EternalRadiance::EternalRadianceEngine::DeclareBrightnessEternal(brightnessId);
}

void EternalRadiancePanel::OnStrengthenEternal(const std::string& intensityId) {
    EternalRadiance::EternalRadianceEngine::StrengthenEternal(intensityId);
}

void EternalRadiancePanel::OnDeepenEternal(const std::string& intensityId) {
    EternalRadiance::EternalRadianceEngine::DeepenEternal(intensityId);
}

void EternalRadiancePanel::OnDeclareIntensityEternal(const std::string& intensityId) {
    EternalRadiance::EternalRadianceEngine::DeclareIntensityEternal(intensityId);
}

void EternalRadiancePanel::OnIlluminateEternal(const std::string& luminescenceId) {
    EternalRadiance::EternalRadianceEngine::IlluminateEternal(luminescenceId);
}

void EternalRadiancePanel::OnRadiateEternal(const std::string& luminescenceId) {
    EternalRadiance::EternalRadianceEngine::RadiateEternal(luminescenceId);
}

void EternalRadiancePanel::OnDeclareLuminescenceEternal(const std::string& luminescenceId) {
    EternalRadiance::EternalRadianceEngine::DeclareLuminescenceEternal(luminescenceId);
}

void EternalRadiancePanel::OnMakeEternalTransparent(const std::string& transparencyId) {
    EternalRadiance::EternalRadianceEngine::MakeEternalTransparent(transparencyId);
}

void EternalRadiancePanel::OnIncreaseEternalClarity(const std::string& transparencyId) {
    EternalRadiance::EternalRadianceEngine::IncreaseEternalClarity(transparencyId);
}

void EternalRadiancePanel::OnDeclareTransparencyEternal(const std::string& transparencyId) {
    EternalRadiance::EternalRadianceEngine::DeclareTransparencyEternal(transparencyId);
}

} // namespace IDE
