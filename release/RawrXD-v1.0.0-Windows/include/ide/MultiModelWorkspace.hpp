#pragma once
#include <windows.h>
#include <vector>
#include <string>
#include <memory>

namespace Sovereign {
namespace IDE {

/**
 * @brief Model instance in workspace
 */
struct ModelInstance {
    std::wstring path;
    std::wstring name;
    HWND viewportHwnd;
    bool active;
    uint64_t loadedTokens;
    float memoryUsageGB;
};

/**
 * @brief Workspace layout
 */
enum class WorkspaceLayout {
    Single,      // One model fullscreen
    SplitH,      // Two models side by side
    SplitV,      // Two models stacked
    Grid,        // Up to 4 models in grid
    Tabbed       // Multiple models in tabs
};

/**
 * @brief Sovereign Multi-Model Workspace
 * 
 * Supports side-by-side model comparison:
 * - Load multiple models simultaneously
 * - Split-screen layouts
 * - Synchronized inference
 * - Performance comparison
 * - Memory usage tracking
 */
class MultiModelWorkspace {
public:
    static MultiModelWorkspace& Instance();

    void Initialize(HWND mainWindow);
    void Shutdown();

    // Model management
    bool LoadModel(const std::wstring& path);
    void UnloadModel(size_t index);
    void UnloadAllModels();
    void ActivateModel(size_t index);
    
    // Layout management
    void SetLayout(WorkspaceLayout layout);
    void CycleLayout();
    
    // Comparison features
    void StartSynchronizedInference();
    void StopSynchronizedInference();
    void ComparePerformance();
    
    // Getters
    size_t GetModelCount() const { return m_models.size(); }
    const ModelInstance* GetModel(size_t index) const;
    const ModelInstance* GetActiveModel() const;
    WorkspaceLayout GetCurrentLayout() const { return m_currentLayout; }
    
    // Viewport management
    void ArrangeViewports();
    void UpdateViewportSizes();

private:
    MultiModelWorkspace() = default;
    
    HWND m_mainWindow = nullptr;
    std::vector<std::unique_ptr<ModelInstance>> m_models;
    size_t m_activeModel = 0;
    WorkspaceLayout m_currentLayout = WorkspaceLayout::Single;
    bool m_synchronizedInference = false;
    
    void CreateViewport(ModelInstance& model);
    void DestroyViewport(ModelInstance& model);
    void CalculateViewportRects(std::vector<RECT>& rects);
};

} // namespace IDE
} // namespace Sovereign
