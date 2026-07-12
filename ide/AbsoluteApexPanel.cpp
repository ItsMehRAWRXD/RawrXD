#include "ide/AbsoluteApexPanel.hpp"
#include "absolute/AbsoluteApexEngine.hpp"
#include "absolute/AbsoluteApexLoop.hpp"
#include <imgui.h>
#include <cstring>

namespace IDE {

bool AbsoluteApexPanel::s_visible = false;
bool AbsoluteApexPanel::s_initialized = false;
char AbsoluteApexPanel::s_nameBuffer[256] = {};
char AbsoluteApexPanel::s_typeBuffer[64] = {};
char AbsoluteApexPanel::s_classBuffer[64] = {};
char AbsoluteApexPanel::s_categoryBuffer[64] = {};
char AbsoluteApexPanel::s_domainBuffer[64] = {};
char AbsoluteApexPanel::s_tierBuffer[64] = {};
std::vector<char> AbsoluteApexPanel::s_jsonBuffer(4096, '\0');
int AbsoluteApexPanel::s_selectedTab = 0;

void AbsoluteApexPanel::Init() {
    if (s_initialized) return;
    s_initialized = true;
    Absolute::AbsoluteApexLoop::Init();
    Absolute::AbsoluteApexLoop::Start();
}

void AbsoluteApexPanel::Shutdown() {
    if (!s_initialized) return;
    Absolute::AbsoluteApexLoop::Shutdown();
    s_initialized = false;
}

void AbsoluteApexPanel::Render() {
    if (!s_visible) return;
    
    ImGui::Begin("Absolute Apex (Layer 64)", &s_visible);
    
    const char* tabs[] = {"Zeniths", "Pinnacles", "Summits", "Peaks", "Achievements", "Metrics", "Report"};
    ImGui::TabBar("ApexTabs", &s_selectedTab, tabs, 7);
    
    switch (s_selectedTab) {
        case 0: RenderZenithManager(); break;
        case 1: RenderPinnacleManager(); break;
        case 2: RenderSummitManager(); break;
        case 3: RenderPeakManager(); break;
        case 4: RenderAchievementManager(); break;
        case 5: RenderMetrics(); break;
        case 6: RenderReport(); break;
    }
    
    ImGui::End();
}

void AbsoluteApexPanel::RenderZenithManager() {
    ImGui::Text("Universal Zenith Management");
    ImGui::Separator();
    
    ImGui::InputText("Zenith Name", s_nameBuffer, sizeof(s_nameBuffer));
    ImGui::InputText("Zenith Type", s_typeBuffer, sizeof(s_typeBuffer));
    
    if (ImGui::Button("Attain Zenith")) {
        std::vector<std::string> prerequisites = {"prereq_1", "prereq_2"};
        Absolute::AbsoluteApexEngine::AttainUniversalZenith(s_nameBuffer, s_typeBuffer, prerequisites);
        memset(s_nameBuffer, 0, sizeof(s_nameBuffer));
        memset(s_typeBuffer, 0, sizeof(s_typeBuffer));
    }
    
    ImGui::Separator();
    ImGui::Text("Attained Zeniths:");
    auto zeniths = Absolute::AbsoluteApexEngine::GetAllZeniths();
    for (const auto& zenith : zeniths) {
        ImGui::Text("%s - %s [%s] (Att: %.2f, Mas: %.2f)", zenith.zenithId.c_str(), zenith.name.c_str(), 
                    zenith.zenithType.c_str(), zenith.attainmentLevel, zenith.masteryScore);
    }
}

void AbsoluteApexPanel::RenderPinnacleManager() {
    ImGui::Text("Cosmic Pinnacle Management");
    ImGui::Separator();
    
    ImGui::InputText("Pinnacle Name", s_nameBuffer, sizeof(s_nameBuffer));
    ImGui::InputText("Pinnacle Class", s_classBuffer, sizeof(s_classBuffer));
    
    if (ImGui::Button("Commit Pinnacle")) {
        std::map<std::string, float> attributes;
        attributes["power"] = 1.0f;
        attributes["wisdom"] = 1.0f;
        Absolute::AbsoluteApexEngine::CommitCosmicPinnacle(s_nameBuffer, s_classBuffer, attributes);
        memset(s_nameBuffer, 0, sizeof(s_nameBuffer));
        memset(s_classBuffer, 0, sizeof(s_classBuffer));
    }
    
    ImGui::Separator();
    ImGui::Text("Committed Pinnacles:");
    auto pinnacles = Absolute::AbsoluteApexEngine::GetAllPinnacles();
    for (const auto& pinnacle : pinnacles) {
        ImGui::Text("%s - %s [%s] (Elev: %.2f, Stab: %.2f)", pinnacle.pinnacleId.c_str(), pinnacle.name.c_str(), 
                    pinnacle.pinnacleClass.c_str(), pinnacle.elevation, pinnacle.stability);
    }
}

void AbsoluteApexPanel::RenderSummitManager() {
    ImGui::Text("Multiversal Summit Management");
    ImGui::Separator();
    
    ImGui::InputText("Summit Name", s_nameBuffer, sizeof(s_nameBuffer));
    ImGui::InputText("Summit Category", s_categoryBuffer, sizeof(s_categoryBuffer));
    
    if (ImGui::Button("Convene Summit")) {
        std::vector<std::string> universes = {"universe_1", "universe_2", "universe_3"};
        Absolute::AbsoluteApexEngine::ConveneMultiversalSummit(s_nameBuffer, s_categoryBuffer, universes);
        memset(s_nameBuffer, 0, sizeof(s_nameBuffer));
        memset(s_categoryBuffer, 0, sizeof(s_categoryBuffer));
    }
    
    ImGui::Separator();
    ImGui::Text("Convened Summits:");
    auto summits = Absolute::AbsoluteApexEngine::GetAllSummits();
    for (const auto& summit : summits) {
        ImGui::Text("%s - %s [%s] (Conv: %.2f, Res: %.2f)", summit.summitId.c_str(), summit.name.c_str(), 
                    summit.summitCategory.c_str(), summit.convergenceIndex, summit.resonanceLevel);
    }
}

void AbsoluteApexPanel::RenderPeakManager() {
    ImGui::Text("Transcendent Peak Management");
    ImGui::Separator();
    
    ImGui::InputText("Peak Name", s_nameBuffer, sizeof(s_nameBuffer));
    ImGui::InputText("Peak Domain", s_domainBuffer, sizeof(s_domainBuffer));
    
    if (ImGui::Button("Ascend Peak")) {
        std::vector<std::string> path = {"step_1", "step_2", "step_3"};
        Absolute::AbsoluteApexEngine::AscendTranscendentPeak(s_nameBuffer, s_domainBuffer, path);
        memset(s_nameBuffer, 0, sizeof(s_nameBuffer));
        memset(s_domainBuffer, 0, sizeof(s_domainBuffer));
    }
    
    ImGui::Separator();
    ImGui::Text("Ascended Peaks:");
    auto peaks = Absolute::AbsoluteApexEngine::GetAllPeaks();
    for (const auto& peak : peaks) {
        ImGui::Text("%s - %s [%s] (Alt: %.2f, Clar: %.2f)", peak.peakId.c_str(), peak.name.c_str(), 
                    peak.peakDomain.c_str(), peak.altitude, peak.clarity);
    }
}

void AbsoluteApexPanel::RenderAchievementManager() {
    ImGui::Text("Apex Achievement Management");
    ImGui::Separator();
    
    ImGui::InputText("Achievement Name", s_nameBuffer, sizeof(s_nameBuffer));
    ImGui::InputText("Achievement Tier", s_tierBuffer, sizeof(s_tierBuffer));
    ImGui::InputTextMultiline("Data (JSON)", s_jsonBuffer.data(), s_jsonBuffer.size());
    
    if (ImGui::Button("Unlock Achievement")) {
        nlohmann::json data = nlohmann::json::parse(s_jsonBuffer.data(), nullptr, false);
        if (!data.is_discarded()) {
            Absolute::AbsoluteApexEngine::UnlockApexAchievement(s_nameBuffer, s_tierBuffer, data);
            memset(s_nameBuffer, 0, sizeof(s_nameBuffer));
            memset(s_tierBuffer, 0, sizeof(s_tierBuffer));
            std::fill(s_jsonBuffer.begin(), s_jsonBuffer.end(), '\0');
        }
    }
    
    ImGui::Separator();
    ImGui::Text("Unlocked Achievements:");
    auto achievements = Absolute::AbsoluteApexEngine::GetAllAchievements();
    for (const auto& achievement : achievements) {
        ImGui::Text("%s - %s [%s] (Rar: %.2f, Prest: %.2f)", achievement.achievementId.c_str(), achievement.name.c_str(), 
                    achievement.achievementTier.c_str(), achievement.rarity, achievement.prestige);
    }
}

void AbsoluteApexPanel::RenderMetrics() {
    ImGui::Text("Apex Metrics");
    ImGui::Separator();
    
    auto metrics = Absolute::AbsoluteApexEngine::GetApexMetrics();
    
    ImGui::Text("Zeniths: %d", metrics["zenithCount"].get<int>());
    ImGui::Text("Pinnacles: %d", metrics["pinnacleCount"].get<int>());
    ImGui::Text("Summits: %d", metrics["summitCount"].get<int>());
    ImGui::Text("Peaks: %d", metrics["peakCount"].get<int>());
    ImGui::Text("Achievements: %d", metrics["achievementCount"].get<int>());
    ImGui::Separator();
    ImGui::Text("Total Attainment: %.4f", metrics["totalAttainment"].get<float>());
    ImGui::Text("Apex Elevation: %.4f", metrics["apexElevation"].get<float>());
    ImGui::Text("Tick Count: %lld", metrics["tickCount"].get<int64_t>());
}

void AbsoluteApexPanel::RenderReport() {
    ImGui::Text("Apex Report");
    ImGui::Separator();
    
    auto report = Absolute::AbsoluteApexEngine::GenerateApexReport();
    std::string reportStr = report.dump(2);
    ImGui::TextWrapped("%s", reportStr.c_str());
}

bool AbsoluteApexPanel::IsVisible() {
    return s_visible;
}

void AbsoluteApexPanel::SetVisible(bool visible) {
    s_visible = visible;
}

void AbsoluteApexPanel::Toggle() {
    s_visible = !s_visible;
}

const char* AbsoluteApexPanel::GetPanelName() {
    return "Absolute Apex";
}

const char* AbsoluteApexPanel::GetShortcut() {
    return "Ctrl+Shift+F36";
}

} // namespace IDE
