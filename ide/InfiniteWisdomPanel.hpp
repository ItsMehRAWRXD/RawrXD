#pragma once

#include <string>
#include <functional>
#include <nlohmann/json.hpp>

namespace InfiniteWisdom {

// Panel tabs
enum class InfiniteWisdomPanelTab {
    InfiniteStructure,
    WisdomInfinite,
    KnowledgeInfinite,
    InsightInfinite,
    TruthInfinite,
    EnlightenmentInfinite,
    Metrics,
    Visualization
};

// Panel class for IDE integration
class InfiniteWisdomPanel {
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
    static void SetActiveTab(InfiniteWisdomPanelTab tab);
    static InfiniteWisdomPanelTab GetActiveTab();
    
    // Callbacks
    using StructureSelectedCallback = std::function<void(const std::string& infiniteId)>;
    using WisdomSelectedCallback = std::function<void(const std::string& wisdomId)>;
    using KnowledgeSelectedCallback = std::function<void(const std::string& knowledgeId)>;
    using InsightSelectedCallback = std::function<void(const std::string& insightId)>;
    using TruthSelectedCallback = std::function<void(const std::string& truthId)>;
    using EnlightenmentSelectedCallback = std::function<void(const std::string& enlightenmentId)>;
    
    static void SetStructureSelectedCallback(const StructureSelectedCallback& callback);
    static void SetWisdomSelectedCallback(const WisdomSelectedCallback& callback);
    static void SetKnowledgeSelectedCallback(const KnowledgeSelectedCallback& callback);
    static void SetInsightSelectedCallback(const InsightSelectedCallback& callback);
    static void SetTruthSelectedCallback(const TruthSelectedCallback& callback);
    static void SetEnlightenmentSelectedCallback(const EnlightenmentSelectedCallback& callback);
    
    // Data refresh
    static void RefreshData();
    static void RefreshStructures();
    static void RefreshWisdomInfinites();
    static void RefreshKnowledgeInfinites();
    static void RefreshInsightInfinites();
    static void RefreshTruthInfinites();
    static void RefreshEnlightenmentInfinites();
    
    // Current data access
    static nlohmann::json GetCurrentMetrics();
    static std::vector<nlohmann::json> GetCurrentStructures();
    static std::vector<nlohmann::json> GetCurrentWisdomInfinites();
    static std::vector<nlohmann::json> GetCurrentKnowledgeInfinites();
    static std::vector<nlohmann::json> GetCurrentInsightInfinites();
    static std::vector<nlohmann::json> GetCurrentTruthInfinites();
    static std::vector<nlohmann::json> GetCurrentEnlightenmentInfinites();
    
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
    static InfiniteWisdomPanelTab s_activeTab;
    static int s_dockingLocation;
    
    // Selection state
    static std::string s_selectedInfiniteId;
    static std::string s_selectedWisdomId;
    static std::string s_selectedKnowledgeId;
    static std::string s_selectedInsightId;
    static std::string s_selectedTruthId;
    static std::string s_selectedEnlightenmentId;
    
    // Callbacks
    static StructureSelectedCallback s_structureCallback;
    static WisdomSelectedCallback s_wisdomCallback;
    static KnowledgeSelectedCallback s_knowledgeCallback;
    static InsightSelectedCallback s_insightCallback;
    static TruthSelectedCallback s_truthCallback;
    static EnlightenmentSelectedCallback s_enlightenmentCallback;
    
    // Cached data
    static nlohmann::json s_cachedMetrics;
    static std::vector<nlohmann::json> s_cachedStructures;
    static std::vector<nlohmann::json> s_cachedWisdomInfinites;
    static std::vector<nlohmann::json> s_cachedKnowledgeInfinites;
    static std::vector<nlohmann::json> s_cachedInsightInfinites;
    static std::vector<nlohmann::json> s_cachedTruthInfinites;
    static std::vector<nlohmann::json> s_cachedEnlightenmentInfinites;
    static std::chrono::steady_clock::time_point s_lastRefresh;
    
    // Input buffers
    static char s_newStructureName[256];
    static char s_newWisdomName[256];
    static char s_newKnowledgeName[256];
    static char s_newInsightName[256];
    static char s_newTruthName[256];
    static char s_newEnlightenmentName[256];
    
    // Tab renderers
    static void RenderInfiniteStructureTab();
    static void RenderWisdomInfiniteTab();
    static void RenderKnowledgeInfiniteTab();
    static void RenderInsightInfiniteTab();
    static void RenderTruthInfiniteTab();
    static void RenderEnlightenmentInfiniteTab();
    static void RenderMetricsTab();
    static void RenderVisualizationTab();
    
    // Detail renderers
    static void RenderStructureDetails(const std::string& infiniteId);
    static void RenderWisdomDetails(const std::string& wisdomId);
    static void RenderKnowledgeDetails(const std::string& knowledgeId);
    static void RenderInsightDetails(const std::string& insightId);
    static void RenderTruthDetails(const std::string& truthId);
    static void RenderEnlightenmentDetails(const std::string& enlightenmentId);
    
    // Dashboard and visualization
    static void RenderMetricsDashboard();
    static void RenderInfiniteVisualization();
};

} // namespace InfiniteWisdom
