#include "InfiniteLightPanel.hpp"
#include "../infinite/InfiniteLightEngine.hpp"
#include "../infinite/InfiniteLightLoop.hpp"
#include <imgui.h>
#include <cstring>
#include <iomanip>
#include <sstream>

namespace IDE {

InfiniteLightPanel::InfiniteLightPanel()
    : m_initialized(false)
    , m_visible(false)
    , m_currentTab(0)
{
    ClearInputBuffers();
    std::memset(m_filterBuffer, 0, sizeof(m_filterBuffer));
}

InfiniteLightPanel::~InfiniteLightPanel() {
    Shutdown();
}

bool InfiniteLightPanel::Initialize() {
    if (m_initialized) return true;
    
    // Initialize Infinite Light engine
    if (!InfiniteLight::InfiniteLightEngine::Initialize()) {
        return false;
    }
    
    // Initialize Infinite Light loop
    InfiniteLight::InfiniteLightLoopConfig loopConfig;
    loopConfig.targetTPS = 60;
    loopConfig.maxFPS = 60;
    loopConfig.enableFrameLimiting = true;
    loopConfig.enableMetrics = true;
    
    if (!InfiniteLight::InfiniteLightLoop::Init(loopConfig)) {
        return false;
    }
    
    m_initialized = true;
    return true;
}

void InfiniteLightPanel::Shutdown() {
    if (!m_initialized) return;
    
    InfiniteLight::InfiniteLightLoop::Shutdown();
    InfiniteLight::InfiniteLightEngine::Shutdown();
    
    m_initialized = false;
}

bool InfiniteLightPanel::IsInitialized() const {
    return m_initialized;
}

void InfiniteLightPanel::Show() {
    m_visible = true;
}

void InfiniteLightPanel::Hide() {
    m_visible = false;
}

void InfiniteLightPanel::ToggleVisibility() {
    m_visible = !m_visible;
}

bool InfiniteLightPanel::IsVisible() const {
    return m_visible;
}

void InfiniteLightPanel::Render() {
    if (!m_visible || !m_initialized) return;
    
    RenderWindow();
}

void InfiniteLightPanel::RenderWindow() {
    ImGui::SetNextWindowSize(ImVec2(900, 700), ImGuiCond_FirstUseEver);
    
    if (ImGui::Begin("Infinite Light (Layer 114)", &m_visible)) {
        RenderTabBar();
        
        switch (static_cast<Tab>(m_currentTab)) {
            case Tab::InfiniteStructures:
                RenderInfiniteStructuresTab();
                break;
            case Tab::RadianceAbsolutes:
                RenderRadianceAbsolutesTab();
                break;
            case Tab::BrillianceAbsolutes:
                RenderBrillianceAbsolutesTab();
                break;
            case Tab::LuminosityAbsolutes:
                RenderLuminosityAbsolutesTab();
                break;
            case Tab::IlluminationAbsolutes:
                RenderIlluminationAbsolutesTab();
                break;
            case Tab::ClarityAbsolutes:
                RenderClarityAbsolutesTab();
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

void InfiniteLightPanel::RenderTabBar() {
    if (ImGui::BeginTabBar("InfiniteLightTabs")) {
        if (ImGui::BeginTabItem("Infinite Structures")) {
            m_currentTab = static_cast<int>(Tab::InfiniteStructures);
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("Radiance Absolutes")) {
            m_currentTab = static_cast<int>(Tab::RadianceAbsolutes);
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("Brilliance Absolutes")) {
            m_currentTab = static_cast<int>(Tab::BrillianceAbsolutes);
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("Luminosity Absolutes")) {
            m_currentTab = static_cast<int>(Tab::LuminosityAbsolutes);
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("Illumination Absolutes")) {
            m_currentTab = static_cast<int>(Tab::IlluminationAbsolutes);
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("Clarity Absolutes")) {
            m_currentTab = static_cast<int>(Tab::ClarityAbsolutes);
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

void InfiniteLightPanel::RenderInfiniteStructuresTab() {
    ImGui::Text("Infinite Light Structures");
    ImGui::Separator();
    
    // Filter
    ImGui::InputText("Filter", m_filterBuffer, sizeof(m_filterBuffer));
    ImGui::SameLine();
    if (ImGui::Button("Clear")) {
        std::memset(m_filterBuffer, 0, sizeof(m_filterBuffer));
    }
    
    ImGui::Spacing();
    
    // Create new
    ImGui::InputText("New Name", m_newInfiniteName, sizeof(m_newInfiniteName));
    ImGui::SameLine();
    if (ImGui::Button("Create")) {
        CreateNewInfiniteStructure();
    }
    
    ImGui::Spacing();
    ImGui::Separator();
    
    // List
    auto infiniteIds = InfiniteLight::InfiniteLightEngine::GetAllInfiniteStructureIds();
    
    ImGui::BeginChild("InfiniteList", ImVec2(300, 0), true);
    for (const auto& id : infiniteIds) {
        auto infinite = InfiniteLight::InfiniteLightEngine::GetInfiniteStructure(id);
        if (infinite && FilterMatches(infinite->name)) {
            bool isSelected = (m_selectedInfiniteId == id);
            if (ImGui::Selectable(infinite->name.c_str(), isSelected)) {
                SelectInfiniteStructure(id);
            }
        }
    }
    ImGui::EndChild();
    
    ImGui::SameLine();
    
    // Details
    ImGui::BeginChild("InfiniteDetails", ImVec2(0, 0), true);
    if (!m_selectedInfiniteId.empty()) {
        RenderInfiniteStructureDetails(m_selectedInfiniteId);
    } else {
        ImGui::Text("Select an infinite structure to view details");
    }
    ImGui::EndChild();
}

void InfiniteLightPanel::RenderRadianceAbsolutesTab() {
    ImGui::Text("Radiance Absolutes");
    ImGui::Separator();
    
    ImGui::InputText("Filter##Radiance", m_filterBuffer, sizeof(m_filterBuffer));
    ImGui::SameLine();
    if (ImGui::Button("Clear##Radiance")) {
        std::memset(m_filterBuffer, 0, sizeof(m_filterBuffer));
    }
    
    ImGui::Spacing();
    
    ImGui::InputText("New Name##Radiance", m_newRadianceName, sizeof(m_newRadianceName));
    ImGui::SameLine();
    if (ImGui::Button("Create##Radiance")) {
        CreateNewRadianceAbsolute();
    }
    
    ImGui::Spacing();
    ImGui::Separator();
    
    auto radianceIds = InfiniteLight::InfiniteLightEngine::GetAllRadianceAbsoluteIds();
    
    ImGui::BeginChild("RadianceList", ImVec2(300, 0), true);
    for (const auto& id : radianceIds) {
        auto radiance = InfiniteLight::InfiniteLightEngine::GetRadianceAbsolute(id);
        if (radiance && FilterMatches(radiance->name)) {
            bool isSelected = (m_selectedRadianceId == id);
            if (ImGui::Selectable(radiance->name.c_str(), isSelected)) {
                SelectRadianceAbsolute(id);
            }
        }
    }
    ImGui::EndChild();
    
    ImGui::SameLine();
    
    ImGui::BeginChild("RadianceDetails", ImVec2(0, 0), true);
    if (!m_selectedRadianceId.empty()) {
        RenderRadianceAbsoluteDetails(m_selectedRadianceId);
    } else {
        ImGui::Text("Select a radiance absolute to view details");
    }
    ImGui::EndChild();
}

void InfiniteLightPanel::RenderBrillianceAbsolutesTab() {
    ImGui::Text("Brilliance Absolutes");
    ImGui::Separator();
    
    ImGui::InputText("Filter##Brilliance", m_filterBuffer, sizeof(m_filterBuffer));
    ImGui::SameLine();
    if (ImGui::Button("Clear##Brilliance")) {
        std::memset(m_filterBuffer, 0, sizeof(m_filterBuffer));
    }
    
    ImGui::Spacing();
    
    ImGui::InputText("New Name##Brilliance", m_newBrillianceName, sizeof(m_newBrillianceName));
    ImGui::SameLine();
    if (ImGui::Button("Create##Brilliance")) {
        CreateNewBrillianceAbsolute();
    }
    
    ImGui::Spacing();
    ImGui::Separator();
    
    auto brillianceIds = InfiniteLight::InfiniteLightEngine::GetAllBrillianceAbsoluteIds();
    
    ImGui::BeginChild("BrillianceList", ImVec2(300, 0), true);
    for (const auto& id : brillianceIds) {
        auto brilliance = InfiniteLight::InfiniteLightEngine::GetBrillianceAbsolute(id);
        if (brilliance && FilterMatches(brilliance->name)) {
            bool isSelected = (m_selectedBrillianceId == id);
            if (ImGui::Selectable(brilliance->name.c_str(), isSelected)) {
                SelectBrillianceAbsolute(id);
            }
        }
    }
    ImGui::EndChild();
    
    ImGui::SameLine();
    
    ImGui::BeginChild("BrillianceDetails", ImVec2(0, 0), true);
    if (!m_selectedBrillianceId.empty()) {
        RenderBrillianceAbsoluteDetails(m_selectedBrillianceId);
    } else {
        ImGui::Text("Select a brilliance absolute to view details");
    }
    ImGui::EndChild();
}

void InfiniteLightPanel::RenderLuminosityAbsolutesTab() {
    ImGui::Text("Luminosity Absolutes");
    ImGui::Separator();
    
    ImGui::InputText("Filter##Luminosity", m_filterBuffer, sizeof(m_filterBuffer));
    ImGui::SameLine();
    if (ImGui::Button("Clear##Luminosity")) {
        std::memset(m_filterBuffer, 0, sizeof(m_filterBuffer));
    }
    
    ImGui::Spacing();
    
    ImGui::InputText("New Name##Luminosity", m_newLuminosityName, sizeof(m_newLuminosityName));
    ImGui::SameLine();
    if (ImGui::Button("Create##Luminosity")) {
        CreateNewLuminosityAbsolute();
    }
    
    ImGui::Spacing();
    ImGui::Separator();
    
    auto luminosityIds = InfiniteLight::InfiniteLightEngine::GetAllLuminosityAbsoluteIds();
    
    ImGui::BeginChild("LuminosityList", ImVec2(300, 0), true);
    for (const auto& id : luminosityIds) {
        auto luminosity = InfiniteLight::InfiniteLightEngine::GetLuminosityAbsolute(id);
        if (luminosity && FilterMatches(luminosity->name)) {
            bool isSelected = (m_selectedLuminosityId == id);
            if (ImGui::Selectable(luminosity->name.c_str(), isSelected)) {
                SelectLuminosityAbsolute(id);
            }
        }
    }
    ImGui::EndChild();
    
    ImGui::SameLine();
    
    ImGui::BeginChild("LuminosityDetails", ImVec2(0, 0), true);
    if (!m_selectedLuminosityId.empty()) {
        RenderLuminosityAbsoluteDetails(m_selectedLuminosityId);
    } else {
        ImGui::Text("Select a luminosity absolute to view details");
    }
    ImGui::EndChild();
}

void InfiniteLightPanel::RenderIlluminationAbsolutesTab() {
    ImGui::Text("Illumination Absolutes");
    ImGui::Separator();
    
    ImGui::InputText("Filter##Illumination", m_filterBuffer, sizeof(m_filterBuffer));
    ImGui::SameLine();
    if (ImGui::Button("Clear##Illumination")) {
        std::memset(m_filterBuffer, 0, sizeof(m_filterBuffer));
    }
    
    ImGui::Spacing();
    
    ImGui::InputText("New Name##Illumination", m_newIlluminationName, sizeof(m_newIlluminationName));
    ImGui::SameLine();
    if (ImGui::Button("Create##Illumination")) {
        CreateNewIlluminationAbsolute();
    }
    
    ImGui::Spacing();
    ImGui::Separator();
    
    auto illuminationIds = InfiniteLight::InfiniteLightEngine::GetAllIlluminationAbsoluteIds();
    
    ImGui::BeginChild("IlluminationList", ImVec2(300, 0), true);
    for (const auto& id : illuminationIds) {
        auto illumination = InfiniteLight::InfiniteLightEngine::GetIlluminationAbsolute(id);
        if (illumination && FilterMatches(illumination->name)) {
            bool isSelected = (m_selectedIlluminationId == id);
            if (ImGui::Selectable(illumination->name.c_str(), isSelected)) {
                SelectIlluminationAbsolute(id);
            }
        }
    }
    ImGui::EndChild();
    
    ImGui::SameLine();
    
    ImGui::BeginChild("IlluminationDetails", ImVec2(0, 0), true);
    if (!m_selectedIlluminationId.empty()) {
        RenderIlluminationAbsoluteDetails(m_selectedIlluminationId);
    } else {
        ImGui::Text("Select an illumination absolute to view details");
    }
    ImGui::EndChild();
}

void InfiniteLightPanel::RenderClarityAbsolutesTab() {
    ImGui::Text("Clarity Absolutes");
    ImGui::Separator();
    
    ImGui::InputText("Filter##Clarity", m_filterBuffer, sizeof(m_filterBuffer));
    ImGui::SameLine();
    if (ImGui::Button("Clear##Clarity")) {
        std::memset(m_filterBuffer, 0, sizeof(m_filterBuffer));
    }
    
    ImGui::Spacing();
    
    ImGui::InputText("New Name##Clarity", m_newClarityName, sizeof(m_newClarityName));
    ImGui::SameLine();
    if (ImGui::Button("Create##Clarity")) {
        CreateNewClarityAbsolute();
    }
    
    ImGui::Spacing();
    ImGui::Separator();
    
    auto clarityIds = InfiniteLight::InfiniteLightEngine::GetAllClarityAbsoluteIds();
    
    ImGui::BeginChild("ClarityList", ImVec2(300, 0), true);
    for (const auto& id : clarityIds) {
        auto clarity = InfiniteLight::InfiniteLightEngine::GetClarityAbsolute(id);
        if (clarity && FilterMatches(clarity->name)) {
            bool isSelected = (m_selectedClarityId == id);
            if (ImGui::Selectable(clarity->name.c_str(), isSelected)) {
                SelectClarityAbsolute(id);
            }
        }
    }
    ImGui::EndChild();
    
    ImGui::SameLine();
    
    ImGui::BeginChild("ClarityDetails", ImVec2(0, 0), true);
    if (!m_selectedClarityId.empty()) {
        RenderClarityAbsoluteDetails(m_selectedClarityId);
    } else {
        ImGui::Text("Select a clarity absolute to view details");
    }
    ImGui::EndChild();
}

void InfiniteLightPanel::RenderMetricsTab() {
    ImGui::Text("Infinite Light Metrics");
    ImGui::Separator();
    
    auto metrics = InfiniteLight::InfiniteLightLoop::GetMetrics();
    
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
    ImGui::Text("Infinite Structures: %zu", InfiniteLight::InfiniteLightEngine::GetAllInfiniteStructureIds().size());
    ImGui::Text("Radiance Absolutes: %zu", InfiniteLight::InfiniteLightEngine::GetAllRadianceAbsoluteIds().size());
    ImGui::Text("Brilliance Absolutes: %zu", InfiniteLight::InfiniteLightEngine::GetAllBrillianceAbsoluteIds().size());
    ImGui::Text("Luminosity Absolutes: %zu", InfiniteLight::InfiniteLightEngine::GetAllLuminosityAbsoluteIds().size());
    ImGui::Text("Illumination Absolutes: %zu", InfiniteLight::InfiniteLightEngine::GetAllIlluminationAbsoluteIds().size());
    ImGui::Text("Clarity Absolutes: %zu", InfiniteLight::InfiniteLightEngine::GetAllClarityAbsoluteIds().size());
}

void InfiniteLightPanel::RenderSettingsTab() {
    ImGui::Text("Infinite Light Settings");
    ImGui::Separator();
    
    auto config = InfiniteLight::InfiniteLightLoop::GetConfig();
    
    bool changed = false;
    
    changed |= ImGui::InputInt("Target TPS", &config.targetTPS);
    changed |= ImGui::InputInt("Max FPS", &config.maxFPS);
    changed |= ImGui::Checkbox("Enable Frame Limiting", &config.enableFrameLimiting);
    changed |= ImGui::Checkbox("Enable Metrics", &config.enableMetrics);
    
    if (changed) {
        InfiniteLight::InfiniteLightLoop::SetConfig(config);
    }
    
    ImGui::Spacing();
    ImGui::Separator();
    
    ImGui::Text("Loop Control:");
    
    if (InfiniteLight::InfiniteLightLoop::IsRunning()) {
        if (ImGui::Button("Stop Loop")) {
            InfiniteLight::InfiniteLightLoop::Stop();
        }
        ImGui::SameLine();
        if (InfiniteLight::InfiniteLightLoop::IsPaused()) {
            if (ImGui::Button("Resume")) {
                InfiniteLight::InfiniteLightLoop::Resume();
            }
        } else {
            if (ImGui::Button("Pause")) {
                InfiniteLight::InfiniteLightLoop::Pause();
            }
        }
    } else {
        if (ImGui::Button("Start Loop")) {
            InfiniteLight::InfiniteLightLoop::Start();
        }
    }
}

void InfiniteLightPanel::RenderInfiniteStructureDetails(const std::string& infiniteId) {
    auto infinite = InfiniteLight::InfiniteLightEngine::GetInfiniteStructure(infiniteId);
    if (!infinite) return;
    
    ImGui::Text("Name: %s", infinite->name.c_str());
    ImGui::Text("ID: %s", infinite->id.c_str());
    ImGui::Text("Created: %s", infinite->createdAt.c_str());
    ImGui::Text("Modified: %s", infinite->modifiedAt.c_str());
    
    ImGui::Spacing();
    ImGui::Separator();
    
    ImGui::Text("Properties:");
    DrawMetric("Glow", infinite->glow);
    DrawMetric("Shine", infinite->shine);
    DrawMetric("Brightness", infinite->brightness);
    DrawMetric("Intensity", infinite->intensity);
    DrawMetric("Lumens", infinite->lumens);
    DrawMetric("Transparency", infinite->transparency);
    
    ImGui::Spacing();
    ImGui::Separator();
    
    ImGui::Text("Actions:");
    if (ImGui::Button("Expand Infinite Light")) {
        OnExpandInfiniteLight(infiniteId);
    }
    if (ImGui::Button("Amplify Radiance")) {
        OnAmplifyRadiance(infiniteId);
    }
    if (ImGui::Button("Increase Brilliance")) {
        OnIncreaseBrilliance(infiniteId);
    }
    if (ImGui::Button("Enhance Luminosity")) {
        OnEnhanceLuminosity(infiniteId);
    }
    if (ImGui::Button("Spread Illumination")) {
        OnSpreadIllumination(infiniteId);
    }
    if (ImGui::Button("Sharpen Clarity")) {
        OnSharpenClarity(infiniteId);
    }
}

void InfiniteLightPanel::RenderRadianceAbsoluteDetails(const std::string& radianceId) {
    auto radiance = InfiniteLight::InfiniteLightEngine::GetRadianceAbsolute(radianceId);
    if (!radiance) return;
    
    ImGui::Text("Name: %s", radiance->name.c_str());
    ImGui::Text("ID: %s", radiance->id.c_str());
    
    ImGui::Spacing();
    ImGui::Separator();
    
    ImGui::Text("Properties:");
    DrawMetric("Glow", radiance->glow);
    DrawMetric("Shine", radiance->shine);
    DrawMetric("Brightness", radiance->brightness);
    DrawMetric("Intensity", radiance->intensity);
    DrawMetric("Lumens", radiance->lumens);
    DrawMetric("Transparency", radiance->transparency);
    
    ImGui::Spacing();
    ImGui::Separator();
    
    ImGui::Text("Actions:");
    if (ImGui::Button("Intensify Glow")) {
        OnIntensifyGlow(radianceId);
    }
    if (ImGui::Button("Amplify Shine")) {
        OnAmplifyShine(radianceId);
    }
    if (ImGui::Button("Declare Radiant")) {
        OnDeclareRadiant(radianceId);
    }
}

void InfiniteLightPanel::RenderBrillianceAbsoluteDetails(const std::string& brillianceId) {
    auto brilliance = InfiniteLight::InfiniteLightEngine::GetBrillianceAbsolute(brillianceId);
    if (!brilliance) return;
    
    ImGui::Text("Name: %s", brilliance->name.c_str());
    ImGui::Text("ID: %s", brilliance->id.c_str());
    
    ImGui::Spacing();
    ImGui::Separator();
    
    ImGui::Text("Properties:");
    DrawMetric("Glow", brilliance->glow);
    DrawMetric("Shine", brilliance->shine);
    DrawMetric("Brightness", brilliance->brightness);
    DrawMetric("Intensity", brilliance->intensity);
    DrawMetric("Lumens", brilliance->lumens);
    DrawMetric("Transparency", brilliance->transparency);
    
    ImGui::Spacing();
    ImGui::Separator();
    
    ImGui::Text("Actions:");
    if (ImGui::Button("Increase Brightness")) {
        OnIncreaseBrightness(brillianceId);
    }
    if (ImGui::Button("Intensify")) {
        OnIntensify(brillianceId);
    }
    if (ImGui::Button("Declare Brilliant")) {
        OnDeclareBrilliant(brillianceId);
    }
}

void InfiniteLightPanel::RenderLuminosityAbsoluteDetails(const std::string& luminosityId) {
    auto luminosity = InfiniteLight::InfiniteLightEngine::GetLuminosityAbsolute(luminosityId);
    if (!luminosity) return;
    
    ImGui::Text("Name: %s", luminosity->name.c_str());
    ImGui::Text("ID: %s", luminosity->id.c_str());
    
    ImGui::Spacing();
    ImGui::Separator();
    
    ImGui::Text("Properties:");
    DrawMetric("Glow", luminosity->glow);
    DrawMetric("Shine", luminosity->shine);
    DrawMetric("Brightness", luminosity->brightness);
    DrawMetric("Intensity", luminosity->intensity);
    DrawMetric("Lumens", luminosity->lumens);
    DrawMetric("Transparency", luminosity->transparency);
    
    ImGui::Spacing();
    ImGui::Separator();
    
    ImGui::Text("Actions:");
    if (ImGui::Button("Brighten")) {
        OnBrighten(luminosityId);
    }
    if (ImGui::Button("Polish Shine")) {
        OnPolishShine(luminosityId);
    }
    if (ImGui::Button("Declare Luminous")) {
        OnDeclareLuminous(luminosityId);
    }
}

void InfiniteLightPanel::RenderIlluminationAbsoluteDetails(const std::string& illuminationId) {
    auto illumination = InfiniteLight::InfiniteLightEngine::GetIlluminationAbsolute(illuminationId);
    if (!illumination) return;
    
    ImGui::Text("Name: %s", illumination->name.c_str());
    ImGui::Text("ID: %s", illumination->id.c_str());
    
    ImGui::Spacing();
    ImGui::Separator();
    
    ImGui::Text("Properties:");
    DrawMetric("Glow", illumination->glow);
    DrawMetric("Shine", illumination->shine);
    DrawMetric("Brightness", illumination->brightness);
    DrawMetric("Intensity", illumination->intensity);
    DrawMetric("Lumens", illumination->lumens);
    DrawMetric("Transparency", illumination->transparency);
    
    ImGui::Spacing();
    ImGui::Separator();
    
    ImGui::Text("Actions:");
    if (ImGui::Button("Enlighten")) {
        OnEnlighten(illuminationId);
    }
    if (ImGui::Button("Reveal")) {
        OnReveal(illuminationId);
    }
    if (ImGui::Button("Declare Illuminated")) {
        OnDeclareIlluminated(illuminationId);
    }
}

void InfiniteLightPanel::RenderClarityAbsoluteDetails(const std::string& clarityId) {
    auto clarity = InfiniteLight::InfiniteLightEngine::GetClarityAbsolute(clarityId);
    if (!clarity) return;
    
    ImGui::Text("Name: %s", clarity->name.c_str());
    ImGui::Text("ID: %s", clarity->id.c_str());
    
    ImGui::Spacing();
    ImGui::Separator();
    
    ImGui::Text("Properties:");
    DrawMetric("Glow", clarity->glow);
    DrawMetric("Shine", clarity->shine);
    DrawMetric("Brightness", clarity->brightness);
    DrawMetric("Intensity", clarity->intensity);
    DrawMetric("Lumens", clarity->lumens);
    DrawMetric("Transparency", clarity->transparency);
    
    ImGui::Spacing();
    ImGui::Separator();
    
    ImGui::Text("Actions:");
    if (ImGui::Button("Make Transparent")) {
        OnMakeTransparent(clarityId);
    }
    if (ImGui::Button("Increase Lucidity")) {
        OnIncreaseLucidity(clarityId);
    }
    if (ImGui::Button("Declare Clear")) {
        OnDeclareClear(clarityId);
    }
}

void InfiniteLightPanel::SelectInfiniteStructure(const std::string& infiniteId) {
    m_selectedInfiniteId = infiniteId;
}

void InfiniteLightPanel::SelectRadianceAbsolute(const std::string& radianceId) {
    m_selectedRadianceId = radianceId;
}

void InfiniteLightPanel::SelectBrillianceAbsolute(const std::string& brillianceId) {
    m_selectedBrillianceId = brillianceId;
}

void InfiniteLightPanel::SelectLuminosityAbsolute(const std::string& luminosityId) {
    m_selectedLuminosityId = luminosityId;
}

void InfiniteLightPanel::SelectIlluminationAbsolute(const std::string& illuminationId) {
    m_selectedIlluminationId = illuminationId;
}

void InfiniteLightPanel::SelectClarityAbsolute(const std::string& clarityId) {
    m_selectedClarityId = clarityId;
}

void InfiniteLightPanel::CreateNewInfiniteStructure() {
    if (std::strlen(m_newInfiniteName) > 0) {
        InfiniteLight::InfiniteLightEngine::CreateInfiniteStructure(m_newInfiniteName);
        std::memset(m_newInfiniteName, 0, sizeof(m_newInfiniteName));
    }
}

void InfiniteLightPanel::CreateNewRadianceAbsolute() {
    if (std::strlen(m_newRadianceName) > 0) {
        InfiniteLight::InfiniteLightEngine::CreateRadianceAbsolute(m_newRadianceName);
        std::memset(m_newRadianceName, 0, sizeof(m_newRadianceName));
    }
}

void InfiniteLightPanel::CreateNewBrillianceAbsolute() {
    if (std::strlen(m_newBrillianceName) > 0) {
        InfiniteLight::InfiniteLightEngine::CreateBrillianceAbsolute(m_newBrillianceName);
        std::memset(m_newBrillianceName, 0, sizeof(m_newBrillianceName));
    }
}

void InfiniteLightPanel::CreateNewLuminosityAbsolute() {
    if (std::strlen(m_newLuminosityName) > 0) {
        InfiniteLight::InfiniteLightEngine::CreateLuminosityAbsolute(m_newLuminosityName);
        std::memset(m_newLuminosityName, 0, sizeof(m_newLuminosityName));
    }
}

void InfiniteLightPanel::CreateNewIlluminationAbsolute() {
    if (std::strlen(m_newIlluminationName) > 0) {
        InfiniteLight::InfiniteLightEngine::CreateIlluminationAbsolute(m_newIlluminationName);
        std::memset(m_newIlluminationName, 0, sizeof(m_newIlluminationName));
    }
}

void InfiniteLightPanel::CreateNewClarityAbsolute() {
    if (std::strlen(m_newClarityName) > 0) {
        InfiniteLight::InfiniteLightEngine::CreateClarityAbsolute(m_newClarityName);
        std::memset(m_newClarityName, 0, sizeof(m_newClarityName));
    }
}

void InfiniteLightPanel::ClearInputBuffers() {
    std::memset(m_newInfiniteName, 0, sizeof(m_newInfiniteName));
    std::memset(m_newRadianceName, 0, sizeof(m_newRadianceName));
    std::memset(m_newBrillianceName, 0, sizeof(m_newBrillianceName));
    std::memset(m_newLuminosityName, 0, sizeof(m_newLuminosityName));
    std::memset(m_newIlluminationName, 0, sizeof(m_newIlluminationName));
    std::memset(m_newClarityName, 0, sizeof(m_newClarityName));
}

bool InfiniteLightPanel::FilterMatches(const std::string& text) const {
    if (std::strlen(m_filterBuffer) == 0) return true;
    return text.find(m_filterBuffer) != std::string::npos;
}

void InfiniteLightPanel::DrawProgressBar(float value, const ImVec4& color) {
    ImGui::PushStyleColor(ImGuiCol_PlotHistogram, color);
    ImGui::ProgressBar(value, ImVec2(-1, 0), "");
    ImGui::PopStyleColor();
}

void InfiniteLightPanel::DrawMetric(const char* label, float value, const char* format) {
    ImGui::Text("%s: ", label);
    ImGui::SameLine();
    ImGui::Text(format, value);
}

// Action handlers
void InfiniteLightPanel::OnExpandInfiniteLight(const std::string& infiniteId) {
    InfiniteLight::InfiniteLightEngine::ExpandInfiniteLight(infiniteId);
}

void InfiniteLightPanel::OnAmplifyRadiance(const std::string& infiniteId) {
    InfiniteLight::InfiniteLightEngine::AmplifyRadiance(infiniteId);
}

void InfiniteLightPanel::OnIncreaseBrilliance(const std::string& infiniteId) {
    InfiniteLight::InfiniteLightEngine::IncreaseBrilliance(infiniteId);
}

void InfiniteLightPanel::OnEnhanceLuminosity(const std::string& infiniteId) {
    InfiniteLight::InfiniteLightEngine::EnhanceLuminosity(infiniteId);
}

void InfiniteLightPanel::OnSpreadIllumination(const std::string& infiniteId) {
    InfiniteLight::InfiniteLightEngine::SpreadIllumination(infiniteId);
}

void InfiniteLightPanel::OnSharpenClarity(const std::string& infiniteId) {
    InfiniteLight::InfiniteLightEngine::SharpenClarity(infiniteId);
}

void InfiniteLightPanel::OnIntensifyGlow(const std::string& radianceId) {
    InfiniteLight::InfiniteLightEngine::IntensifyGlow(radianceId);
}

void InfiniteLightPanel::OnAmplifyShine(const std::string& radianceId) {
    InfiniteLight::InfiniteLightEngine::AmplifyShine(radianceId);
}

void InfiniteLightPanel::OnDeclareRadiant(const std::string& radianceId) {
    InfiniteLight::InfiniteLightEngine::DeclareRadiant(radianceId);
}

void InfiniteLightPanel::OnIncreaseBrightness(const std::string& brillianceId) {
    InfiniteLight::InfiniteLightEngine::IncreaseBrightness(brillianceId);
}

void InfiniteLightPanel::OnIntensify(const std::string& brillianceId) {
    InfiniteLight::InfiniteLightEngine::Intensify(brillianceId);
}

void InfiniteLightPanel::OnDeclareBrilliant(const std::string& brillianceId) {
    InfiniteLight::InfiniteLightEngine::DeclareBrilliant(brillianceId);
}

void InfiniteLightPanel::OnBrighten(const std::string& luminosityId) {
    InfiniteLight::InfiniteLightEngine::Brighten(luminosityId);
}

void InfiniteLightPanel::OnPolishShine(const std::string& luminosityId) {
    InfiniteLight::InfiniteLightEngine::PolishShine(luminosityId);
}

void InfiniteLightPanel::OnDeclareLuminous(const std::string& luminosityId) {
    InfiniteLight::InfiniteLightEngine::DeclareLuminous(luminosityId);
}

void InfiniteLightPanel::OnEnlighten(const std::string& illuminationId) {
    InfiniteLight::InfiniteLightEngine::Enlighten(illuminationId);
}

void InfiniteLightPanel::OnReveal(const std::string& illuminationId) {
    InfiniteLight::InfiniteLightEngine::Reveal(illuminationId);
}

void InfiniteLightPanel::OnDeclareIlluminated(const std::string& illuminationId) {
    InfiniteLight::InfiniteLightEngine::DeclareIlluminated(illuminationId);
}

void InfiniteLightPanel::OnMakeTransparent(const std::string& clarityId) {
    InfiniteLight::InfiniteLightEngine::MakeTransparent(clarityId);
}

void InfiniteLightPanel::OnIncreaseLucidity(const std::string& clarityId) {
    InfiniteLight::InfiniteLightEngine::IncreaseLucidity(clarityId);
}

void InfiniteLightPanel::OnDeclareClear(const std::string& clarityId) {
    InfiniteLight::InfiniteLightEngine::DeclareClear(clarityId);
}

} // namespace IDE
