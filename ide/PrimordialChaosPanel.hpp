#pragma once

#include <cstring>
#include <vector>
#include <functional>
#include <nlohmann/json.hpp>

// Forward declarations for ImGui
struct ImVec2;
struct ImVec4;

namespace PrimordialChaos {

// Panel states
enum class PrimordialChaosPanelTab {
    PrimordialStructure,
    ChaosPrimordial,
    VoidPrimordial,
    AbyssPrimordial,
    FluxPrimordial,
    Metrics,
    Visualization
};

// Primordial Chaos Panel - IDE interface for primordial chaos operations
class PrimordialChaosPanel {
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
    static void SetActiveTab(PrimordialChaosPanelTab tab);
    static PrimordialChaosPanelTab GetActiveTab();
    
    // Event callbacks
    using StructureSelectedCallback = std::function<void(const std::string& primordialId)>;
    using ChaosSelectedCallback = std::function<void(const std::string& chaosId)>;
    using VoidSelectedCallback = std::function<void(const std::string& voidId)>;
    using AbyssSelectedCallback = std::function<void(const std::string& abyssId)>;
    using FluxSelectedCallback = std::function<void(const std::string& fluxId)>;
    
    static void SetStructureSelectedCallback(const StructureSelectedCallback& callback);
    static void SetChaosSelectedCallback(const ChaosSelectedCallback& callback);
    static void SetVoidSelectedCallback(const VoidSelectedCallback& callback);
    static void SetAbyssSelectedCallback(const AbyssSelectedCallback& callback);
    static void SetFluxSelectedCallback(const FluxSelectedCallback& callback);
    
    // Refresh data
    static void RefreshData();
    static void RefreshStructures();
    static void RefreshChaosPrimordials();
    static void RefreshVoidPrimordials();
    static void RefreshAbyssPrimordials();
    static void RefreshFluxPrimordials();
    
    // Getters for current data
    static nlohmann::json GetCurrentMetrics();
    static std::vector<nlohmann::json> GetCurrentStructures();
    static std::vector<nlohmann::json> GetCurrentChaosPrimordials();
    static std::vector<nlohmann::json> GetCurrentVoidPrimordials();
    static std::vector<nlohmann::json> GetCurrentAbyssPrimordials();
    static std::vector<nlohmann::json> GetCurrentFluxPrimordials();
    
    // Hotkey handling
    static void RegisterHotkey();
    static void UnregisterHotkey();
    static void HandleHotkey();
    
    // Docking
    static void SetDockingLocation(int location);
    static int GetDockingLocation();
    
private:
    // Tab renderers
    static void RenderPrimordialStructureTab();
    static void RenderChaosPrimordialTab();
    static void RenderVoidPrimordialTab();
    static void RenderAbyssPrimordialTab();
    static void RenderFluxPrimordialTab();
    static void RenderMetricsTab();
    static void RenderVisualizationTab();
    
    // Helper functions
    static void RenderStructureList();
    static void RenderStructureDetails(const std::string& primordialId);
    static void RenderChaosList();
    static void RenderChaosDetails(const std::string& chaosId);
    static void RenderVoidList();
    static void RenderVoidDetails(const std::string& voidId);
    static void RenderAbyssList();
    static void RenderAbyssDetails(const std::string& abyssId);
    static void RenderFluxList();
    static void RenderFluxDetails(const std::string& fluxId);
    static void RenderMetricsDashboard();
    static void RenderPrimordialVisualization();
    
    // UI helpers
    static void DrawProgressBar(float value, const ImVec2& size, const ImVec4& color);
    static void DrawPrimordialOrb(float primordiality, float chaos, float voidness, float abyss, float flux);
    static void DrawChaosSwirl(float chaos, float disorder, bool isChaotic);
    
    // State
    static bool s_initialized;
    static bool s_visible;
    static PrimordialChaosPanelTab s_activeTab;
    static int s_dockingLocation;
    
    // Selected items
    static std::string s_selectedPrimordialId;
    static std::string s_selectedChaosId;
    static std::string s_selectedVoidId;
    static std::string s_selectedAbyssId;
    static std::string s_selectedFluxId;
    
    // Callbacks
    static StructureSelectedCallback s_structureCallback;
    static ChaosSelectedCallback s_chaosCallback;
    static VoidSelectedCallback s_voidCallback;
    static AbyssSelectedCallback s_abyssCallback;
    static FluxSelectedCallback s_fluxCallback;
    
    // Cached data
    static nlohmann::json s_cachedMetrics;
    static std::vector<nlohmann::json> s_cachedStructures;
    static std::vector<nlohmann::json> s_cachedChaosPrimordials;
    static std::vector<nlohmann::json> s_cachedVoidPrimordials;
    static std::vector<nlohmann::json> s_cachedAbyssPrimordials;
    static std::vector<nlohmann::json> s_cachedFluxPrimordials;
    static std::chrono::steady_clock::time_point s_lastRefresh;
    
    // Input buffers
    static char s_newStructureName[256];
    static char s_newChaosName[256];
    static char s_newVoidName[256];
    static char s_newAbyssName[256];
    static char s_newFluxName[256];
};

} // namespace PrimordialChaos
