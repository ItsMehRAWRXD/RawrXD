#pragma once

#include <cstring>
#include <vector>
#include <memory>
#include <functional>

// Forward declarations for ImGui
struct ImVec2;
struct ImVec4;

namespace OmniscientContinuum {
    class OmniscientContinuumEngine;
    struct OmniscientField;
    struct ContinuumNode;
    struct AwarenessStream;
    struct PerceptionWave;
    struct ResonanceMatrix;
    struct ContinuityTensor;
    struct OmniscientClarity;
}

namespace IDE {

// Panel for Omniscient Continuum (Layer 117)
class OmniscientContinuumPanel {
public:
    OmniscientContinuumPanel();
    ~OmniscientContinuumPanel();

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
    static const char* GetHotkey() { return "Ctrl+Shift+F117"; }
    static int GetLayerNumber() { return 117; }
    static const char* GetLayerName() { return "Omniscient Continuum"; }

    // Selection
    void SelectOmniscientField(const std::string& fieldId);
    void SelectContinuumNode(const std::string& nodeId);
    void SelectAwarenessStream(const std::string& streamId);
    void SelectPerceptionWave(const std::string& waveId);
    void SelectResonanceMatrix(const std::string& matrixId);
    void SelectContinuityTensor(const std::string& tensorId);
    void SelectOmniscientClarity(const std::string& clarityId);

    // Creation helpers
    void CreateNewOmniscientField();
    void CreateNewContinuumNode();
    void CreateNewAwarenessStream();
    void CreateNewPerceptionWave();
    void CreateNewResonanceMatrix();
    void CreateNewContinuityTensor();
    void CreateNewOmniscientClarity();

private:
    bool m_initialized;
    bool m_visible;

    // Tab state
    int m_currentTab;
    enum class Tab {
        OmniscientField = 0,
        ContinuumNodes,
        AwarenessStreams,
        PerceptionWaves,
        ResonanceMatrix,
        ContinuityTensor,
        OmniscientClarity,
        Metrics,
        Settings,
        Count
    };

    // Selection state
    std::string m_selectedFieldId;
    std::string m_selectedNodeId;
    std::string m_selectedStreamId;
    std::string m_selectedWaveId;
    std::string m_selectedMatrixId;
    std::string m_selectedTensorId;
    std::string m_selectedClarityId;

    // Input buffers for creation
    char m_newFieldName[256];
    char m_newNodeName[256];
    char m_newStreamName[256];
    char m_newWaveName[256];
    char m_newMatrixName[256];
    char m_newTensorName[256];
    char m_newClarityName[256];

    // Filter/search
    char m_filterBuffer[256];

    // Rendering helpers
    void RenderTabBar();
    void RenderOmniscientFieldTab();
    void RenderContinuumNodesTab();
    void RenderAwarenessStreamsTab();
    void RenderPerceptionWavesTab();
    void RenderResonanceMatrixTab();
    void RenderContinuityTensorTab();
    void RenderOmniscientClarityTab();
    void RenderMetricsTab();
    void RenderSettingsTab();

    // Detail rendering
    void RenderOmniscientFieldDetails(const std::string& fieldId);
    void RenderContinuumNodeDetails(const std::string& nodeId);
    void RenderAwarenessStreamDetails(const std::string& streamId);
    void RenderPerceptionWaveDetails(const std::string& waveId);
    void RenderResonanceMatrixDetails(const std::string& matrixId);
    void RenderContinuityTensorDetails(const std::string& tensorId);
    void RenderOmniscientClarityDetails(const std::string& clarityId);

    // Action handlers
    void OnExpandContinuum(const std::string& fieldId);
    void OnMergeAwareness(const std::string& nodeId);
    void OnAmplifyResonance(const std::string& fieldId);
    void OnStrengthenContinuity(const std::string& fieldId);
    void OnClarifyOmniscience(const std::string& fieldId);
    void OnStabilizeField(const std::string& matrixId);
    void OnUnifyNodes(const std::string& nodeId);

    // Utility
    void ClearInputBuffers();
    bool FilterMatches(const std::string& text) const;
    void DrawProgressBar(float value, const ImVec4& color);
    void DrawMetric(const char* label, float value, const char* format = "%.2f");
    void DrawMatrixVisualization(const OmniscientContinuum::ResonanceMatrix& matrix);
    void DrawTensorVisualization(const OmniscientContinuum::ContinuityTensor& tensor);
};

} // namespace IDE
