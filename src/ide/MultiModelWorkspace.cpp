#include "ide/MultiModelWorkspace.hpp"
#include "sovereign/Beaconism.hpp"
#include "sovereign/ModelRegistry.hpp"
#include <algorithm>

namespace Sovereign {
namespace IDE {

MultiModelWorkspace& MultiModelWorkspace::Instance() {
    static MultiModelWorkspace instance;
    return instance;
}

void MultiModelWorkspace::Initialize(HWND mainWindow) {
    m_mainWindow = mainWindow;
}

void MultiModelWorkspace::Shutdown() {
    UnloadAllModels();
}

bool MultiModelWorkspace::LoadModel(const std::wstring& path) {
    if (m_models.size() >= 4) {
        // Maximum 4 models in workspace
        return false;
    }
    
    auto model = std::make_unique<ModelInstance>();
    model->path = path;
    
    // Extract filename as name
    size_t pos = path.find_last_of(L"\\/");
    if (pos != std::wstring::npos) {
        model->name = path.substr(pos + 1);
    } else {
        model->name = path;
    }
    
    model->active = false;
    model->loadedTokens = 0;
    model->memoryUsageGB = 0.0f;
    
    // Create viewport window
    CreateViewport(*model);
    
    // Load the model
    if (!ModelRegistry::Load(path.c_str())) {
        DestroyViewport(*model);
        return false;
    }
    
    // Update model info
    model->loadedTokens = ModelRegistry::GetTokenCount();
    model->memoryUsageGB = ModelRegistry::GetMemoryUsageGB();
    
    m_models.push_back(std::move(model));
    
    // Activate the new model
    ActivateModel(m_models.size() - 1);
    
    // Arrange viewports
    ArrangeViewports();
    
    Beaconism::Emit(BeaconID::ModelStart, static_cast<uint32_t>(m_models.size()));
    
    return true;
}

void MultiModelWorkspace::UnloadModel(size_t index) {
    if (index >= m_models.size()) return;
    
    DestroyViewport(*m_models[index]);
    m_models.erase(m_models.begin() + index);
    
    // Update active model index
    if (m_activeModel >= m_models.size()) {
        m_activeModel = m_models.size() > 0 ? m_models.size() - 1 : 0;
    }
    
    if (m_models.size() > 0) {
        ActivateModel(m_activeModel);
    }
    
    ArrangeViewports();
}

void MultiModelWorkspace::UnloadAllModels() {
    for (auto& model : m_models) {
        DestroyViewport(*model);
    }
    m_models.clear();
    m_activeModel = 0;
}

void MultiModelWorkspace::ActivateModel(size_t index) {
    if (index >= m_models.size()) return;
    
    // Deactivate current
    if (m_activeModel < m_models.size()) {
        m_models[m_activeModel]->active = false;
    }
    
    // Activate new
    m_activeModel = index;
    m_models[m_activeModel]->active = true;
    
    // Bring to front
    SetWindowPos(m_models[m_activeModel]->viewportHwnd, HWND_TOP, 0, 0, 0, 0,
        SWP_NOMOVE | SWP_NOSIZE);
}

void MultiModelWorkspace::SetLayout(WorkspaceLayout layout) {
    m_currentLayout = layout;
    ArrangeViewports();
}

void MultiModelWorkspace::CycleLayout() {
    switch (m_currentLayout) {
        case WorkspaceLayout::Single:
            m_currentLayout = WorkspaceLayout::SplitH;
            break;
        case WorkspaceLayout::SplitH:
            m_currentLayout = WorkspaceLayout::SplitV;
            break;
        case WorkspaceLayout::SplitV:
            m_currentLayout = WorkspaceLayout::Grid;
            break;
        case WorkspaceLayout::Grid:
            m_currentLayout = WorkspaceLayout::Tabbed;
            break;
        case WorkspaceLayout::Tabbed:
            m_currentLayout = WorkspaceLayout::Single;
            break;
    }
    ArrangeViewports();
}

void MultiModelWorkspace::StartSynchronizedInference() {
    m_synchronizedInference = true;
    Beaconism::Emit(BeaconID::SmoketestStart, 0xSYNC);
}

void MultiModelWorkspace::StopSynchronizedInference() {
    m_synchronizedInference = false;
    Beaconism::Emit(BeaconID::SmoketestDone, 0xSYNC);
}

void MultiModelWorkspace::ComparePerformance() {
    // Emit performance comparison beacons
    for (size_t i = 0; i < m_models.size(); i++) {
        const auto& model = m_models[i];
        Beaconism::Emit(BeaconID::ProfilerTokPerSec, 
            static_cast<uint32_t>(model->loadedTokens));
    }
}

const ModelInstance* MultiModelWorkspace::GetModel(size_t index) const {
    if (index >= m_models.size()) return nullptr;
    return m_models[index].get();
}

const ModelInstance* MultiModelWorkspace::GetActiveModel() const {
    if (m_activeModel >= m_models.size()) return nullptr;
    return m_models[m_activeModel].get();
}

void MultiModelWorkspace::ArrangeViewports() {
    if (m_models.empty()) return;
    
    std::vector<RECT> rects;
    CalculateViewportRects(rects);
    
    for (size_t i = 0; i < m_models.size() && i < rects.size(); i++) {
        const auto& rect = rects[i];
        SetWindowPos(m_models[i]->viewportHwnd, nullptr,
            rect.left, rect.top,
            rect.right - rect.left,
            rect.bottom - rect.top,
            SWP_NOZORDER);
        ShowWindow(m_models[i]->viewportHwnd, SW_SHOW);
    }
    
    // Hide extra viewports
    for (size_t i = rects.size(); i < m_models.size(); i++) {
        ShowWindow(m_models[i]->viewportHwnd, SW_HIDE);
    }
}

void MultiModelWorkspace::UpdateViewportSizes() {
    ArrangeViewports();
}

void MultiModelWorkspace::CreateViewport(ModelInstance& model) {
    WNDCLASSEXW wc = { sizeof(wc) };
    wc.lpfnWndProc = DefWindowProcW;
    wc.hInstance = GetModuleHandle(nullptr);
    wc.lpszClassName = L"SovereignModelViewport";
    wc.hbrBackground = (HBRUSH)GetStockObject(GRAY_BRUSH);
    
    RegisterClassExW(&wc);
    
    model.viewportHwnd = CreateWindowExW(
        WS_EX_CLIENTEDGE,
        L"SovereignModelViewport",
        model.name.c_str(),
        WS_CHILD | WS_VISIBLE | WS_CLIPCHILDREN,
        0, 0, 400, 300,
        m_mainWindow, nullptr, GetModuleHandle(nullptr), nullptr
    );
}

void MultiModelWorkspace::DestroyViewport(ModelInstance& model) {
    if (model.viewportHwnd) {
        DestroyWindow(model.viewportHwnd);
        model.viewportHwnd = nullptr;
    }
}

void MultiModelWorkspace::CalculateViewportRects(std::vector<RECT>& rects) {
    if (!m_mainWindow) return;
    
    RECT clientRect;
    GetClientRect(m_mainWindow, &clientRect);
    
    int width = clientRect.right - clientRect.left;
    int height = clientRect.bottom - clientRect.top;
    
    switch (m_currentLayout) {
        case WorkspaceLayout::Single:
            if (m_models.size() > 0) {
                rects.push_back({ 0, 0, width, height });
            }
            break;
            
        case WorkspaceLayout::SplitH:
            if (m_models.size() >= 2) {
                int halfWidth = width / 2;
                rects.push_back({ 0, 0, halfWidth, height });
                rects.push_back({ halfWidth, 0, width, height });
            } else if (m_models.size() == 1) {
                rects.push_back({ 0, 0, width, height });
            }
            break;
            
        case WorkspaceLayout::SplitV:
            if (m_models.size() >= 2) {
                int halfHeight = height / 2;
                rects.push_back({ 0, 0, width, halfHeight });
                rects.push_back({ 0, halfHeight, width, height });
            } else if (m_models.size() == 1) {
                rects.push_back({ 0, 0, width, height });
            }
            break;
            
        case WorkspaceLayout::Grid:
            {
                int halfWidth = width / 2;
                int halfHeight = height / 2;
                
                size_t count = std::min(m_models.size(), size_t(4));
                for (size_t i = 0; i < count; i++) {
                    int col = i % 2;
                    int row = i / 2;
                    rects.push_back({
                        col * halfWidth,
                        row * halfHeight,
                        (col + 1) * halfWidth,
                        (row + 1) * halfHeight
                    });
                }
            }
            break;
            
        case WorkspaceLayout::Tabbed:
            // All models share same rect, only active one is visible
            for (size_t i = 0; i < m_models.size(); i++) {
                rects.push_back({ 0, 0, width, height });
            }
            break;
    }
}

} // namespace IDE
} // namespace Sovereign
