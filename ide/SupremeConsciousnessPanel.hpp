#pragma once

#include <cstring>
#include <vector>
#include <memory>
#include <functional>

// Forward declarations for ImGui
struct ImVec2;
struct ImVec4;

namespace SupremeConsciousness {
    class SupremeConsciousnessEngine;
    struct SupremeConsciousnessStructure;
    struct AwarenessSupreme;
    struct CognitionSupreme;
    struct PerceptionSupreme;
    struct UnderstandingSupreme;
    struct WisdomSupreme;
    struct KnowledgeSupreme;
}

namespace IDE {

// Panel for Supreme Consciousness (Layer 116)
class SupremeConsciousnessPanel {
public:
    SupremeConsciousnessPanel();
    ~SupremeConsciousnessPanel();

    // Initialization
    bool Initialize();
    void Shutdown();
    bool IsInitialized() const;

    // Rendering
    void Render();
    void RenderWindow();

    // Visibility
    void Show();
    void Hide();
    void ToggleVisibility();
    bool IsVisible() const;

    // Hotkey
    static const char* GetHotkey() { return "Ctrl+Shift+F116"; }
    static int GetLayerNumber() { return 116; }
    static const char* GetLayerName() { return "Supreme Consciousness"; }

    // Selection
    void SelectSupremeConsciousnessStructure(const std::string& supremeId);
    void SelectAwarenessSupreme(const std::string& awarenessId);
    void SelectCognitionSupreme(const std::string& cognitionId);
    void SelectPerceptionSupreme(const std::string& perceptionId);
    void SelectUnderstandingSupreme(const std::string& understandingId);
    void SelectWisdomSupreme(const std::string& wisdomId);
    void SelectKnowledgeSupreme(const std::string& knowledgeId);

    // Creation helpers
    void CreateNewSupremeConsciousnessStructure();
    void CreateNewAwarenessSupreme();
    void CreateNewCognitionSupreme();
    void CreateNewPerceptionSupreme();
    void CreateNewUnderstandingSupreme();
    void CreateNewWisdomSupreme();
    void CreateNewKnowledgeSupreme();

private:
    bool m_initialized;
    bool m_visible;

    // Tab state
    int m_currentTab;
    enum class Tab {
        SupremeStructures = 0,
        AwarenessSupremes,
        CognitionSupremes,
        PerceptionSupremes,
        UnderstandingSupremes,
        WisdomSupremes,
        KnowledgeSupremes,
        Metrics,
        Settings,
        Count
    };

    // Selection state
    std::string m_selectedSupremeId;
    std::string m_selectedAwarenessId;
    std::string m_selectedCognitionId;
    std::string m_selectedPerceptionId;
    std::string m_selectedUnderstandingId;
    std::string m_selectedWisdomId;
    std::string m_selectedKnowledgeId;

    // Input buffers for creation
    char m_newSupremeName[256];
    char m_newAwarenessName[256];
    char m_newCognitionName[256];
    char m_newPerceptionName[256];
    char m_newUnderstandingName[256];
    char m_newWisdomName[256];
    char m_newKnowledgeName[256];

    // Filter/search
    char m_filterBuffer[256];

    // Rendering helpers
    void RenderTabBar();
    void RenderSupremeStructuresTab();
    void RenderAwarenessSupremesTab();
    void RenderCognitionSupremesTab();
    void RenderPerceptionSupremesTab();
    void RenderUnderstandingSupremesTab();
    void RenderWisdomSupremesTab();
    void RenderKnowledgeSupremesTab();
    void RenderMetricsTab();
    void RenderSettingsTab();

    // Detail rendering
    void RenderSupremeConsciousnessStructureDetails(const std::string& supremeId);
    void RenderAwarenessSupremeDetails(const std::string& awarenessId);
    void RenderCognitionSupremeDetails(const std::string& cognitionId);
    void RenderPerceptionSupremeDetails(const std::string& perceptionId);
    void RenderUnderstandingSupremeDetails(const std::string& understandingId);
    void RenderWisdomSupremeDetails(const std::string& wisdomId);
    void RenderKnowledgeSupremeDetails(const std::string& knowledgeId);

    // Action handlers
    void OnExpandSupremeConsciousness(const std::string& supremeId);
    void OnAmplifyAwareness(const std::string& supremeId);
    void OnIncreaseCognition(const std::string& supremeId);
    void OnEnhancePerception(const std::string& supremeId);
    void OnDeepenUnderstanding(const std::string& supremeId);
    void OnCultivateWisdom(const std::string& supremeId);
    void OnAccumulateKnowledge(const std::string& supremeId);

    void OnIntensifyAwarenessSupreme(const std::string& awarenessId);
    void OnBroadenAwarenessSupreme(const std::string& awarenessId);
    void OnDeclareAwarenessSupreme(const std::string& awarenessId);

    void OnSharpenCognitionSupreme(const std::string& cognitionId);
    void OnExpandCognitionSupreme(const std::string& cognitionId);
    void OnDeclareCognitionSupreme(const std::string& cognitionId);

    void OnRefinePerceptionSupreme(const std::string& perceptionId);
    void OnHeightenPerceptionSupreme(const std::string& perceptionId);
    void OnDeclarePerceptionSupreme(const std::string& perceptionId);

    void OnDeepenUnderstandingSupreme(const std::string& understandingId);
    void OnClarifyUnderstandingSupreme(const std::string& understandingId);
    void OnDeclareUnderstandingSupreme(const std::string& understandingId);

    void OnCultivateWisdomSupreme(const std::string& wisdomId);
    void OnApplyWisdomSupreme(const std::string& wisdomId);
    void OnDeclareWisdomSupreme(const std::string& wisdomId);

    void OnAccumulateKnowledgeSupreme(const std::string& knowledgeId);
    void OnOrganizeKnowledgeSupreme(const std::string& knowledgeId);
    void OnDeclareKnowledgeSupreme(const std::string& knowledgeId);

    // Utility
    void ClearInputBuffers();
    bool FilterMatches(const std::string& text) const;
    void DrawProgressBar(float value, const ImVec4& color);
    void DrawMetric(const char* label, float value, const char* format = "%.2f");
};

} // namespace IDE
