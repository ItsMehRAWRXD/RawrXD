#pragma once

#include <cstring>
#include <functional>
#include <nlohmann/json.hpp>

namespace SupremeBeing {

// Panel tabs
enum class SupremeBeingPanelTab {
    SupremeStructure,
    BeingSupreme,
    EssenceSupreme,
    NatureSupreme,
    SpiritSupreme,
    WillSupreme,
    Metrics,
    Visualization
};

// Panel class for IDE integration
class SupremeBeingPanel {
public:
    // Initialization
    static void Init();
    static void Shutdown();
    static bool IsInitialized();
    
    // Rendering
    static void Render();
    static void Render(bool* p_open);
    
    // Visibility
    static void Show();
    static void Hide();
    static void ToggleVisibility();
    static bool IsVisible();
    
    // Tab management
    static void SetActiveTab(SupremeBeingPanelTab tab);
    static SupremeBeingPanelTab GetActiveTab();
    
    // Callbacks
    using StructureSelectedCallback = std::function<void(const std::string& supremeId)>;
    using BeingSelectedCallback = std::function<void(const std::string& beingId)>;
    using EssenceSelectedCallback = std::function<void(const std::string& essenceId)>;
    using NatureSelectedCallback = std::function<void(const std::string& natureId)>;
    using SpiritSelectedCallback = std::function<void(const std::string& spiritId)>;
    using WillSelectedCallback = std::function<void(const std::string& willId)>;
    
    static void SetStructureSelectedCallback(const StructureSelectedCallback& callback);
    static void SetBeingSelectedCallback(const BeingSelectedCallback& callback);
    static void SetEssenceSelectedCallback(const EssenceSelectedCallback& callback);
    static void SetNatureSelectedCallback(const NatureSelectedCallback& callback);
    static void SetSpiritSelectedCallback(const SpiritSelectedCallback& callback);
    static void SetWillSelectedCallback(const WillSelectedCallback& callback);
    
    // Data refresh
    static void RefreshData();
    static void RefreshStructures();
    static void RefreshBeingSupremes();
    static void RefreshEssenceSupremes();
    static void RefreshNatureSupremes();
    static void RefreshSpiritSupremes();
    static void RefreshWillSupremes();
    
    // Current data access
    static nlohmann::json GetCurrentMetrics();
    static std::vector<nlohmann::json> GetCurrentStructures();
    static std::vector<nlohmann::json> GetCurrentBeingSupremes();
    static std::vector<nlohmann::json> GetCurrentEssenceSupremes();
    static std::vector<nlohmann::json> GetCurrentNatureSupremes();
    static std::vector<nlohmann::json> GetCurrentSpiritSupremes();
    static std::vector<nlohmann::json> GetCurrentWillSupremes();
    
    // Hotkey support
    static void RegisterHotkey();
    static void UnregisterHotkey();
    static void HandleHotkey();
    
    // Docking
    static void SetDockingLocation(int location);
    static int GetDockingLocation();
    
private:
    static bool s_initialized;
    static bool s_visible;
    static SupremeBeingPanelTab s_activeTab;
    static int s_dockingLocation;
    
    // Selection state
    static std::string s_selectedSupremeId;
    static std::string s_selectedBeingId;
    static std::string s_selectedEssenceId;
    static std::string s_selectedNatureId;
    static std::string s_selectedSpiritId;
    static std::string s_selectedWillId;
    
    // Callbacks
    static StructureSelectedCallback s_structureCallback;
    static BeingSelectedCallback s_beingCallback;
    static EssenceSelectedCallback s_essenceCallback;
    static NatureSelectedCallback s_natureCallback;
    static SpiritSelectedCallback s_spiritCallback;
    static WillSelectedCallback s_willCallback;
    
    // Cached data
    static nlohmann::json s_cachedMetrics;
    static std::vector<nlohmann::json> s_cachedStructures;
    static std::vector<nlohmann::json> s_cachedBeingSupremes;
    static std::vector<nlohmann::json> s_cachedEssenceSupremes;
    static std::vector<nlohmann::json> s_cachedNatureSupremes;
    static std::vector<nlohmann::json> s_cachedSpiritSupremes;
    static std::vector<nlohmann::json> s_cachedWillSupremes;
    
    // Input buffers
    static char s_newStructureName[256];
    static char s_newBeingName[256];
    static char s_newEssenceName[256];
    static char s_newNatureName[256];
    static char s_newSpiritName[256];
    static char s_newWillName[256];
    
    // Tab renderers
    static void RenderSupremeStructureTab();
    static void RenderBeingSupremeTab();
    static void RenderEssenceSupremeTab();
    static void RenderNatureSupremeTab();
    static void RenderSpiritSupremeTab();
    static void RenderWillSupremeTab();
    static void RenderMetricsTab();
    static void RenderVisualizationTab();
    
    // Detail renderers
    static void RenderStructureDetails(const std::string& supremeId);
    static void RenderBeingDetails(const std::string& beingId);
    static void RenderEssenceDetails(const std::string& essenceId);
    static void RenderNatureDetails(const std::string& natureId);
    static void RenderSpiritDetails(const std::string& spiritId);
    static void RenderWillDetails(const std::string& willId);
    
    // Dashboard and visualization
    static void RenderMetricsDashboard();
    static void RenderSupremeVisualization();
};

} // namespace SupremeBeing
