#pragma once

#include <imgui.h>
#include <cstring>
#include <vector>
#include <nlohmann/json.hpp>

namespace IDE {

class TranscendentDominionPanel {
public:
    static void Init();
    static void Shutdown();
    static void Render();
    static bool IsVisible();
    static void SetVisible(bool visible);
    static void ToggleVisibility();
    static const char* GetPanelName();
    static void OnSovereignEnthroned(const std::string& sovereignId);
    static void OnAuthorityEstablished(const std::string& authorityId);
    static void OnGovernanceEnacted(const std::string& governanceId);
    static void OnLawDecreed(const std::string& lawId);
    static void OnRealmManifested(const std::string& realmId);

private:
    static void RenderRealitySovereignTab();
    static void RenderDimensionalAuthorityTab();
    static void RenderExistenceGovernanceTab();
    static void RenderCosmicLawTab();
    static void RenderTranscendentRealmTab();
    static void RenderDominionMetricsTab();
    static void RenderDominionVisualizationTab();

    static bool s_visible;
    static bool s_initialized;
    static int s_selectedTab;
    static char s_nameBuffer[256];
    static char s_jurisdictionBuffer[512];
    static char s_edictBuffer[1024];
    static char s_realityIdBuffer[256];
    static char s_entityIdBuffer[256];
    static char s_beingIdBuffer[256];
    static char s_attributeKeyBuffer[256];
    static char s_attributeValueBuffer[512];
    static int s_dimensionCountInput;
    static float s_authorityInput;
    static float s_dominionInput;
    static float s_majestyInput;
    static float s_dimensionalReachInput;
    static float s_temporalScopeInput;
    static float s_spatialScopeInput;
    static float s_enforcementInput;
    static float s_complianceInput;
    static float s_orderInput;
    static float s_universalityInput;
    static float s_immutabilityInput;
    static float s_transcendenceInput;
    static float s_infinityInput;
    static float s_eternityInput;
    static std::string s_selectedSovereignId;
    static std::string s_selectedAuthorityId;
    static std::string s_selectedGovernanceId;
    static std::string s_selectedLawId;
    static std::string s_selectedRealmId;
    static std::vector<nlohmann::json> s_dominionEvents;
};

} // namespace IDE
