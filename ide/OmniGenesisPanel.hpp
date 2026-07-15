#pragma once

#include <cstring>
#include <vector>
#include <functional>
#include <nlohmann/json.hpp>

// Forward declarations for ImGui
struct ImVec2;
struct ImVec4;

namespace OmniGenesis {

// Panel states
enum class OmniGenesisPanelTab {
    OmniStructure,
    GenesisOmni,
    CreationOmni,
    OriginOmni,
    SourceOmni,
    Metrics,
    Visualization
};

// Omni Genesis Panel - IDE interface for omni genesis operations
class OmniGenesisPanel {
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
    static void SetActiveTab(OmniGenesisPanelTab tab);
    static OmniGenesisPanelTab GetActiveTab();
    
    // Event callbacks
    using StructureSelectedCallback = std::function<void(const std::string& omniId)>;
    using GenesisSelectedCallback = std::function<void(const std::string& genesisId)>;
    using CreationSelectedCallback = std::function<void(const std::string& creationId)>;
    using OriginSelectedCallback = std::function<void(const std::string& originId)>;
    using SourceSelectedCallback = std::function<void(const std::string& sourceId)>;
    
    static void SetStructureSelectedCallback(const StructureSelectedCallback& callback);
    static void SetGenesisSelectedCallback(const GenesisSelectedCallback& callback);
    static void SetCreationSelectedCallback(const CreationSelectedCallback& callback);
    static void SetOriginSelectedCallback(const OriginSelectedCallback& callback);
    static void SetSourceSelectedCallback(const SourceSelectedCallback& callback);
    
    // Refresh data
    static void RefreshData();
    static void RefreshStructures();
    static void RefreshGenesisOmnis();
    static void RefreshCreationOmnis();
    static void RefreshOriginOmnis();
    static void RefreshSourceOmnis();
    
    // Getters for current data
    static nlohmann::json GetCurrentMetrics();
    static std::vector<nlohmann::json> GetCurrentStructures();
    static std::vector<nlohmann::json> GetCurrentGenesisOmnis();
    static std::vector<nlohmann::json> GetCurrentCreationOmnis();
    static std::vector<nlohmann::json> GetCurrentOriginOmnis();
    static std::vector<nlohmann::json> GetCurrentSourceOmnis();
    
    // Hotkey handling
    static void RegisterHotkey();
    static void UnregisterHotkey();
    static void HandleHotkey();
    
    // Docking
    static void SetDockingLocation(int location);
    static int GetDockingLocation();
    
private:
    // Tab renderers
    static void RenderOmniStructureTab();
    static void RenderGenesisOmniTab();
    static void RenderCreationOmniTab();
    static void RenderOriginOmniTab();
    static void RenderSourceOmniTab();
    static void RenderMetricsTab();
    static void RenderVisualizationTab();
    
    // Helper functions
    static void RenderStructureList();
    static void RenderStructureDetails(const std::string& omniId);
    static void RenderGenesisList();
    static void RenderGenesisDetails(const std::string& genesisId);
    static void RenderCreationList();
    static void RenderCreationDetails(const std::string& creationId);
    static void RenderOriginList();
    static void RenderOriginDetails(const std::string& originId);
    static void RenderSourceList();
    static void RenderSourceDetails(const std::string& sourceId);
    static void RenderMetricsDashboard();
    static void RenderOmniVisualization();
    
    // UI helpers
    static void DrawProgressBar(float value, const ImVec2& size, const ImVec4& color);
    static void DrawOmniOrb(float omniscience, float genesis, float creation, float origin, float source);
    static void DrawGenesisSpark(float genesis, float birth, bool isBorn);
    
    // State
    static bool s_initialized;
    static bool s_visible;
    static OmniGenesisPanelTab s_activeTab;
    static int s_dockingLocation;
    
    // Selected items
    static std::string s_selectedOmniId;
    static std::string s_selectedGenesisId;
    static std::string s_selectedCreationId;
    static std::string s_selectedOriginId;
    static std::string s_selectedSourceId;
    
    // Callbacks
    static StructureSelectedCallback s_structureCallback;
    static GenesisSelectedCallback s_genesisCallback;
    static CreationSelectedCallback s_creationCallback;
    static OriginSelectedCallback s_originCallback;
    static SourceSelectedCallback s_sourceCallback;
    
    // Cached data
    static nlohmann::json s_cachedMetrics;
    static std::vector<nlohmann::json> s_cachedStructures;
    static std::vector<nlohmann::json> s_cachedGenesisOmnis;
    static std::vector<nlohmann::json> s_cachedCreationOmnis;
    static std::vector<nlohmann::json> s_cachedOriginOmnis;
    static std::vector<nlohmann::json> s_cachedSourceOmnis;
    static std::chrono::steady_clock::time_point s_lastRefresh;
    
    // Input buffers
    static char s_newStructureName[256];
    static char s_newGenesisName[256];
    static char s_newCreationName[256];
    static char s_newOriginName[256];
    static char s_newSourceName[256];
};

} // namespace OmniGenesis
