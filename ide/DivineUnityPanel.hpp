#pragma once

#include <string>
#include <vector>
#include <functional>
#include <nlohmann/json.hpp>

// Forward declarations for ImGui
struct ImVec2;
struct ImVec4;

namespace DivineUnity {

// Panel states
enum class DivineUnityPanelTab {
    DivineStructure,
    UnityDivine,
    GraceDivine,
    LightDivine,
    TruthDivine,
    Metrics,
    Visualization
};

// Divine Unity Panel - IDE interface for divine unity operations
class DivineUnityPanel {
public:
    // Initialization
    static void Init();
    static void Shutdown();
    static bool IsInitialized();
    
    // Main render function
    static void Render();
    static void Render(bool* p_open);
    
    // Visibility
    static void Show();
    static void Hide();
    static void ToggleVisibility();
    static bool IsVisible();
    
    // Tab management
    static void SetActiveTab(DivineUnityPanelTab tab);
    static DivineUnityPanelTab GetActiveTab();
    
    // Event callbacks
    using StructureSelectedCallback = std::function<void(const std::string& divineId)>;
    using UnitySelectedCallback = std::function<void(const std::string& unityId)>;
    using GraceSelectedCallback = std::function<void(const std::string& graceId)>;
    using LightSelectedCallback = std::function<void(const std::string& lightId)>;
    using TruthSelectedCallback = std::function<void(const std::string& truthId)>;
    
    static void SetStructureSelectedCallback(const StructureSelectedCallback& callback);
    static void SetUnitySelectedCallback(const UnitySelectedCallback& callback);
    static void SetGraceSelectedCallback(const GraceSelectedCallback& callback);
    static void SetLightSelectedCallback(const LightSelectedCallback& callback);
    static void SetTruthSelectedCallback(const TruthSelectedCallback& callback);
    
    // Refresh data
    static void RefreshData();
    static void RefreshStructures();
    static void RefreshUnityDivines();
    static void RefreshGraceDivines();
    static void RefreshLightDivines();
    static void RefreshTruthDivines();
    
    // Getters for current data
    static nlohmann::json GetCurrentMetrics();
    static std::vector<nlohmann::json> GetCurrentStructures();
    static std::vector<nlohmann::json> GetCurrentUnityDivines();
    static std::vector<nlohmann::json> GetCurrentGraceDivines();
    static std::vector<nlohmann::json> GetCurrentLightDivines();
    static std::vector<nlohmann::json> GetCurrentTruthDivines();
    
    // Hotkey handling
    static void RegisterHotkey();
    static void UnregisterHotkey();
    static void HandleHotkey();
    
    // Docking
    static void SetDockingLocation(int location);
    static int GetDockingLocation();
    
private:
    // Tab renderers
    static void RenderDivineStructureTab();
    static void RenderUnityDivineTab();
    static void RenderGraceDivineTab();
    static void RenderLightDivineTab();
    static void RenderTruthDivineTab();
    static void RenderMetricsTab();
    static void RenderVisualizationTab();
    
    // Helper functions
    static void RenderStructureList();
    static void RenderStructureDetails(const std::string& divineId);
    static void RenderUnityList();
    static void RenderUnityDetails(const std::string& unityId);
    static void RenderGraceList();
    static void RenderGraceDetails(const std::string& graceId);
    static void RenderLightList();
    static void RenderLightDetails(const std::string& lightId);
    static void RenderTruthList();
    static void RenderTruthDetails(const std::string& truthId);
    static void RenderMetricsDashboard();
    static void RenderDivineVisualization();
    
    // UI helpers
    static void DrawProgressBar(float value, const ImVec2& size, const ImVec4& color);
    static void DrawDivineOrb(float divinity, float unity, float grace, float light, float truth);
    static void DrawUnityRay(float unity, float cohesion, bool isUnified);
    
    // State
    static bool s_initialized;
    static bool s_visible;
    static DivineUnityPanelTab s_activeTab;
    static int s_dockingLocation;
    
    // Selected items
    static std::string s_selectedDivineId;
    static std::string s_selectedUnityId;
    static std::string s_selectedGraceId;
    static std::string s_selectedLightId;
    static std::string s_selectedTruthId;
    
    // Callbacks
    static StructureSelectedCallback s_structureCallback;
    static UnitySelectedCallback s_unityCallback;
    static GraceSelectedCallback s_graceCallback;
    static LightSelectedCallback s_lightCallback;
    static TruthSelectedCallback s_truthCallback;
    
    // Cached data
    static nlohmann::json s_cachedMetrics;
    static std::vector<nlohmann::json> s_cachedStructures;
    static std::vector<nlohmann::json> s_cachedUnityDivines;
    static std::vector<nlohmann::json> s_cachedGraceDivines;
    static std::vector<nlohmann::json> s_cachedLightDivines;
    static std::vector<nlohmann::json> s_cachedTruthDivines;
    static std::chrono::steady_clock::time_point s_lastRefresh;
    
    // Input buffers
    static char s_newStructureName[256];
    static char s_newUnityName[256];
    static char s_newGraceName[256];
    static char s_newLightName[256];
    static char s_newTruthName[256];
};

} // namespace DivineUnity
