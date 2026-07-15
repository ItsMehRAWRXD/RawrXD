#pragma once

#include <cstring>
#include <vector>
#include <functional>
#include <nlohmann/json.hpp>

// Forward declarations for ImGui
struct ImVec2;
struct ImVec4;

namespace CosmicSynthesis {

// Panel states
enum class CosmicSynthesisPanelTab {
    CosmicStructure,
    SynthesisCosmic,
    HarmonyCosmic,
    BalanceCosmic,
    UnityCosmic,
    Metrics,
    Visualization
};

// Cosmic Synthesis Panel - IDE interface for cosmic synthesis operations
class CosmicSynthesisPanel {
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
    static void SetActiveTab(CosmicSynthesisPanelTab tab);
    static CosmicSynthesisPanelTab GetActiveTab();
    
    // Event callbacks
    using StructureSelectedCallback = std::function<void(const std::string& cosmicId)>;
    using SynthesisSelectedCallback = std::function<void(const std::string& synthesisId)>;
    using HarmonySelectedCallback = std::function<void(const std::string& harmonyId)>;
    using BalanceSelectedCallback = std::function<void(const std::string& balanceId)>;
    using UnitySelectedCallback = std::function<void(const std::string& unityId)>;
    
    static void SetStructureSelectedCallback(const StructureSelectedCallback& callback);
    static void SetSynthesisSelectedCallback(const SynthesisSelectedCallback& callback);
    static void SetHarmonySelectedCallback(const HarmonySelectedCallback& callback);
    static void SetBalanceSelectedCallback(const BalanceSelectedCallback& callback);
    static void SetUnitySelectedCallback(const UnitySelectedCallback& callback);
    
    // Refresh data
    static void RefreshData();
    static void RefreshStructures();
    static void RefreshSynthesisCosmics();
    static void RefreshHarmonyCosmics();
    static void RefreshBalanceCosmics();
    static void RefreshUnityCosmics();
    
    // Getters for current data
    static nlohmann::json GetCurrentMetrics();
    static std::vector<nlohmann::json> GetCurrentStructures();
    static std::vector<nlohmann::json> GetCurrentSynthesisCosmics();
    static std::vector<nlohmann::json> GetCurrentHarmonyCosmics();
    static std::vector<nlohmann::json> GetCurrentBalanceCosmics();
    static std::vector<nlohmann::json> GetCurrentUnityCosmics();
    
    // Hotkey handling
    static void RegisterHotkey();
    static void UnregisterHotkey();
    static void HandleHotkey();
    
    // Docking
    static void SetDockingLocation(int location);
    static int GetDockingLocation();
    
private:
    // Tab renderers
    static void RenderCosmicStructureTab();
    static void RenderSynthesisCosmicTab();
    static void RenderHarmonyCosmicTab();
    static void RenderBalanceCosmicTab();
    static void RenderUnityCosmicTab();
    static void RenderMetricsTab();
    static void RenderVisualizationTab();
    
    // Helper functions
    static void RenderStructureList();
    static void RenderStructureDetails(const std::string& cosmicId);
    static void RenderSynthesisList();
    static void RenderSynthesisDetails(const std::string& synthesisId);
    static void RenderHarmonyList();
    static void RenderHarmonyDetails(const std::string& harmonyId);
    static void RenderBalanceList();
    static void RenderBalanceDetails(const std::string& balanceId);
    static void RenderUnityList();
    static void RenderUnityDetails(const std::string& unityId);
    static void RenderMetricsDashboard();
    static void RenderCosmicVisualization();
    
    // UI helpers
    static void DrawProgressBar(float value, const ImVec2& size, const ImVec4& color);
    static void DrawCosmicOrb(float cosmicness, float synthesis, float harmony, float balance, float unity);
    static void DrawSynthesisRing(float synthesis, float integration, bool isSynthesized);
    
    // State
    static bool s_initialized;
    static bool s_visible;
    static CosmicSynthesisPanelTab s_activeTab;
    static int s_dockingLocation;
    
    // Selected items
    static std::string s_selectedCosmicId;
    static std::string s_selectedSynthesisId;
    static std::string s_selectedHarmonyId;
    static std::string s_selectedBalanceId;
    static std::string s_selectedUnityId;
    
    // Callbacks
    static StructureSelectedCallback s_structureCallback;
    static SynthesisSelectedCallback s_synthesisCallback;
    static HarmonySelectedCallback s_harmonyCallback;
    static BalanceSelectedCallback s_balanceCallback;
    static UnitySelectedCallback s_unityCallback;
    
    // Cached data
    static nlohmann::json s_cachedMetrics;
    static std::vector<nlohmann::json> s_cachedStructures;
    static std::vector<nlohmann::json> s_cachedSynthesisCosmics;
    static std::vector<nlohmann::json> s_cachedHarmonyCosmics;
    static std::vector<nlohmann::json> s_cachedBalanceCosmics;
    static std::vector<nlohmann::json> s_cachedUnityCosmics;
    static std::chrono::steady_clock::time_point s_lastRefresh;
    
    // Input buffers
    static char s_newStructureName[256];
    static char s_newSynthesisName[256];
    static char s_newHarmonyName[256];
    static char s_newBalanceName[256];
    static char s_newUnityName[256];
};

} // namespace CosmicSynthesis
