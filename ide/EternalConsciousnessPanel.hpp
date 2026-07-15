#pragma once

#include <string>
#include <functional>
#include <nlohmann/json.hpp>

namespace EternalConsciousness {

// Panel tabs
enum class EternalConsciousnessPanelTab {
    EternalStructure,
    ConsciousnessEternal,
    AwarenessEternal,
    PresenceEternal,
    ExistenceEternal,
    ContinuityEternal,
    Metrics,
    Visualization
};

// Panel class for IDE integration
class EternalConsciousnessPanel {
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
    static void SetActiveTab(EternalConsciousnessPanelTab tab);
    static EternalConsciousnessPanelTab GetActiveTab();
    
    // Callbacks
    using StructureSelectedCallback = std::function<void(const std::string& eternalId)>;
    using ConsciousnessSelectedCallback = std::function<void(const std::string& consciousnessId)>;
    using AwarenessSelectedCallback = std::function<void(const std::string& awarenessId)>;
    using PresenceSelectedCallback = std::function<void(const std::string& presenceId)>;
    using ExistenceSelectedCallback = std::function<void(const std::string& existenceId)>;
    using ContinuitySelectedCallback = std::function<void(const std::string& continuityId)>;
    
    static void SetStructureSelectedCallback(const StructureSelectedCallback& callback);
    static void SetConsciousnessSelectedCallback(const ConsciousnessSelectedCallback& callback);
    static void SetAwarenessSelectedCallback(const AwarenessSelectedCallback& callback);
    static void SetPresenceSelectedCallback(const PresenceSelectedCallback& callback);
    static void SetExistenceSelectedCallback(const ExistenceSelectedCallback& callback);
    static void SetContinuitySelectedCallback(const ContinuitySelectedCallback& callback);
    
    // Data refresh
    static void RefreshData();
    static void RefreshStructures();
    static void RefreshConsciousnessEternals();
    static void RefreshAwarenessEternals();
    static void RefreshPresenceEternals();
    static void RefreshExistenceEternals();
    static void RefreshContinuityEternals();
    
    // Current data access
    static nlohmann::json GetCurrentMetrics();
    static std::vector<nlohmann::json> GetCurrentStructures();
    static std::vector<nlohmann::json> GetCurrentConsciousnessEternals();
    static std::vector<nlohmann::json> GetCurrentAwarenessEternals();
    static std::vector<nlohmann::json> GetCurrentPresenceEternals();
    static std::vector<nlohmann::json> GetCurrentExistenceEternals();
    static std::vector<nlohmann::json> GetCurrentContinuityEternals();
    
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
    static EternalConsciousnessPanelTab s_activeTab;
    static int s_dockingLocation;
    
    // Selection state
    static std::string s_selectedEternalId;
    static std::string s_selectedConsciousnessId;
    static std::string s_selectedAwarenessId;
    static std::string s_selectedPresenceId;
    static std::string s_selectedExistenceId;
    static std::string s_selectedContinuityId;
    
    // Callbacks
    static StructureSelectedCallback s_structureCallback;
    static ConsciousnessSelectedCallback s_consciousnessCallback;
    static AwarenessSelectedCallback s_awarenessCallback;
    static PresenceSelectedCallback s_presenceCallback;
    static ExistenceSelectedCallback s_existenceCallback;
    static ContinuitySelectedCallback s_continuityCallback;
    
    // Cached data
    static nlohmann::json s_cachedMetrics;
    static std::vector<nlohmann::json> s_cachedStructures;
    static std::vector<nlohmann::json> s_cachedConsciousnessEternals;
    static std::vector<nlohmann::json> s_cachedAwarenessEternals;
    static std::vector<nlohmann::json> s_cachedPresenceEternals;
    static std::vector<nlohmann::json> s_cachedExistenceEternals;
    static std::vector<nlohmann::json> s_cachedContinuityEternals;
    
    // Input buffers
    static char s_newStructureName[256];
    static char s_newConsciousnessName[256];
    static char s_newAwarenessName[256];
    static char s_newPresenceName[256];
    static char s_newExistenceName[256];
    static char s_newContinuityName[256];
    
    // Tab renderers
    static void RenderEternalStructureTab();
    static void RenderConsciousnessEternalTab();
    static void RenderAwarenessEternalTab();
    static void RenderPresenceEternalTab();
    static void RenderExistenceEternalTab();
    static void RenderContinuityEternalTab();
    static void RenderMetricsTab();
    static void RenderVisualizationTab();
    
    // Detail renderers
    static void RenderStructureDetails(const std::string& eternalId);
    static void RenderConsciousnessDetails(const std::string& consciousnessId);
    static void RenderAwarenessDetails(const std::string& awarenessId);
    static void RenderPresenceDetails(const std::string& presenceId);
    static void RenderExistenceDetails(const std::string& existenceId);
    static void RenderContinuityDetails(const std::string& continuityId);
    
    // Dashboard and visualization
    static void RenderMetricsDashboard();
    static void RenderEternalVisualization();
};

} // namespace EternalConsciousness
