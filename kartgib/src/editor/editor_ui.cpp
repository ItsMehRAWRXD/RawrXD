#include "editor_ui.hpp"
#include <imgui.h>
#include <imgui_internal.h>
#include <imgui_impl_win32.h>
#include <imgui_impl_dx11.h>
#include <algorithm>
#include <fstream>
#include <sstream>
#include <iostream>
#include <ctime>
#include <iomanip>
#include <commdlg.h>
#include <shlobj.h>

namespace kartgib::editor {

EditorUI::EditorUI(const EditorConfig& config) : config(config) {}

EditorUI::~EditorUI() {
    shutdown();
}

bool EditorUI::initialize(HINSTANCE hInstance, int nCmdShow) {
    hinstance = hInstance;
    
    // Register window class
    WNDCLASSEX wc = { sizeof(WNDCLASSEX), CS_CLASSDC, nullptr, 0, 0,
                      hInstance, nullptr, nullptr, nullptr, nullptr,
                      L"KartGibEditor", nullptr };
    RegisterClassEx(&wc);
    
    hwnd = CreateWindow(wc.lpszClassName, L"KartGib Editor", WS_OVERLAPPEDWINDOW,
                        100, 100, config.windowWidth, config.windowHeight,
                        nullptr, nullptr, hInstance, nullptr);
    
    if (!hwnd) return false;
    
    ShowWindow(hwnd, nCmdShow);
    UpdateWindow(hwnd);
    
    // Initialize Direct3D
    DXGI_SWAP_CHAIN_DESC sd = {};
    sd.BufferCount = 2;
    sd.BufferDesc.Width = config.windowWidth;
    sd.BufferDesc.Height = config.windowHeight;
    sd.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
    sd.BufferDesc.RefreshRate.Numerator = 60;
    sd.BufferDesc.RefreshRate.Denominator = 1;
    sd.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
    sd.OutputWindow = hwnd;
    sd.SampleDesc.Count = config.msaaSamples;
    sd.SampleDesc.Quality = 0;
    sd.Windowed = TRUE;
    sd.SwapEffect = DXGI_SWAP_EFFECT_DISCARD;
    
    D3D11CreateDeviceAndSwapChain(nullptr, D3D_DRIVER_TYPE_HARDWARE, nullptr, 0, nullptr, 0,
                                  D3D11_SDK_VERSION, &sd, &swapChain, &d3dDevice, nullptr, &d3dContext);
    
    ID3D11Texture2D* pBackBuffer;
    swapChain->GetBuffer(0, IID_PPV_ARGS(&pBackBuffer));
    d3dDevice->CreateRenderTargetView(pBackBuffer, nullptr, &renderTargetView);
    pBackBuffer->Release();
    
    // Create depth stencil
    D3D11_TEXTURE2D_DESC depthDesc = {};
    depthDesc.Width = config.windowWidth;
    depthDesc.Height = config.windowHeight;
    depthDesc.MipLevels = 1;
    depthDesc.ArraySize = 1;
    depthDesc.Format = DXGI_FORMAT_D24_UNORM_S8_UINT;
    depthDesc.SampleDesc.Count = config.msaaSamples;
    depthDesc.SampleDesc.Quality = 0;
    depthDesc.Usage = D3D11_USAGE_DEFAULT;
    depthDesc.BindFlags = D3D11_BIND_DEPTH_STENCIL;
    d3dDevice->CreateTexture2D(&depthDesc, nullptr, &depthStencil);
    d3dDevice->CreateDepthStencilView(depthStencil, nullptr, &depthStencilView);
    
    d3dContext->OMSetRenderTargets(1, &renderTargetView, depthStencilView);
    
    // Initialize ImGui
    IMGUI_CHECKVERSION();
    imguiContext = ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO();
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;
    io.ConfigFlags |= ImGuiConfigFlags_DockingEnable;
    io.ConfigFlags |= ImGuiConfigFlags_ViewportsEnable;
    
    ImGui_ImplWin32_Init(hwnd);
    ImGui_ImplDX11_Init(d3dDevice.Get(), d3dContext.Get());
    
    // Set up default panels
    panels.clear();
    panels.push_back({"hierarchy", "Hierarchy", DockPanel::Type::Hierarchy, true, true, 200, 150, {10, 100}, {300, 500}, nullptr});
    panels.push_back({"inspector", "Inspector", DockPanel::Type::Inspector, true, true, 250, 400, {320, 100}, {350, 600}, nullptr});
    panels.push_back({"project", "Project", DockPanel::Type::Project, true, true, 250, 300, {680, 100}, {350, 500}, nullptr});
    panels.push_back({"console", "Console", DockPanel::Type::Console, true, true, 250, 200, {1040, 100}, {500, 300}, nullptr});
    panels.push_back({"scene", "Scene", DockPanel::Type::Scene, true, true, 400, 400, {10, 620}, {800, 450}, nullptr});
    panels.push_back({"game", "Game", DockPanel::Type::Game, true, true, 400, 400, {820, 620}, {800, 450}, nullptr});
    
    // Apply theme
    applyThemeColors(darkTheme);
    
    running = true;
    initialized = true;
    return true;
}

void EditorUI::shutdown() {
    ImGui_ImplDX11_Shutdown();
    ImGui_ImplWin32_Shutdown();
    ImGui::DestroyContext(imguiContext);
    
    if (renderTargetView) renderTargetView->Release();
    if (depthStencilView) depthStencilView->Release();
    if (depthStencil) depthStencil->Release();
    if (swapChain) swapChain->Release();
    if (d3dContext) d3dContext->Release();
    if (d3dDevice) d3dDevice->Release();
    
    if (hwnd) DestroyWindow(hwnd);
    running = false;
}

void EditorUI::run() {
    MSG msg = {};
    while (running && msg.message != WM_QUIT) {
        if (PeekMessage(&msg, nullptr, 0, 0, PM_REMOVE)) {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        } else {
            newFrame();
            render();
            endFrame();
        }
    }
}

void EditorUI::newFrame() {
    ImGui_ImplDX11_NewFrame();
    ImGui_ImplWin32_NewFrame();
    ImGui::NewFrame();
    
    // Update FPS counter
    static float lastTime = 0.0f;
    static int frameCount = 0;
    frameCount++;
    float currentTime = (float)std::clock() / CLOCKS_PER_SEC;
    if (currentTime - lastTime >= 1.0f) {
        fps = frameCount / (currentTime - lastTime);
        frameCount = 0;
        lastTime = currentTime;
    }
    
    handleInput();
    processKeyboardShortcuts();
}

void EditorUI::endFrame() {
    ImGui::Render();
    d3dContext->OMSetRenderTargets(1, &renderTargetView, depthStencilView);
    d3dContext->ClearRenderTargetView(renderTargetView, (float*)&clearColor);
    d3dContext->ClearDepthStencilView(depthStencilView, D3D11_CLEAR_DEPTH | D3D11_CLEAR_STENCIL, 1.0f, 0);
    ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());
    
    if (imguiContext->IO.ConfigFlags & ImGuiConfigFlags_ViewportsEnable) {
        ImGui::UpdatePlatformWindows();
        ImGui::RenderPlatformWindowsDefault();
    }
    
    swapChain->Present(config.vsync ? 1 : 0, 0);
}

void EditorUI::drawMainMenuBar() {
    if (ImGui::BeginMainMenuBar()) {
        if (ImGui::BeginMenu("File")) {
            if (ImGui::MenuItem("New Scene", "Ctrl+N")) {
                scene = new Scene();
                selectedEntity = 0;
            }
            if (ImGui::MenuItem("Open...", "Ctrl+O")) {
                // Open file dialog
                OPENFILENAME ofn = {};
                char szFile[260] = "";
                ofn.lStructSize = sizeof(ofn);
                ofn.hwndOwner = hwnd;
                ofn.lpstrFile = szFile;
                ofn.nMaxFile = sizeof(szFile);
                ofn.lpstrFilter = "Scene Files (*.wfs)\0*.wfs\0All Files\0*.*\0";
                ofn.nFilterIndex = 1;
                ofn.lpstrFileTitle = nullptr;
                ofn.nMaxFileTitle = 0;
                ofn.lpstrInitialDir = nullptr;
                ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;
                if (GetOpenFileName(&ofn)) {
                    scene = new Scene();
                    scene->load(ofn.lpstrFile);
                }
            }
            if (ImGui::MenuItem("Save", "Ctrl+S")) {
                // Save scene
            }
            if (ImGui::MenuItem("Save As...", "Ctrl+Shift+S")) {
                OPENFILENAME ofn = {};
                char szFile[260] = "";
                ofn.lStructSize = sizeof(ofn);
                ofn.hwndOwner = hwnd;
                ofn.lpstrFile = szFile;
                ofn.nMaxFile = sizeof(szFile);
                ofn.lpstrFilter = "Scene Files (*.wfs)\0*.wfs\0All Files\0*.*\0";
                ofn.nFilterIndex = 1;
                if (GetSaveFileName(&ofn)) {
                    scene->save(ofn.lpstrFile);
                }
            }
            ImGui::Separator();
            if (ImGui::MenuItem("Exit", "Alt+F4")) {
                running = false;
            }
            ImGui::EndMenu();
        }
        
        if (ImGui::BeginMenu("Edit")) {
            if (ImGui::MenuItem("Undo", "Ctrl+Z")) {}
            if (ImGui::MenuItem("Redo", "Ctrl+Y")) {}
            ImGui::Separator();
            if (ImGui::MenuItem("Cut", "Ctrl+X")) {}
            if (ImGui::MenuItem("Copy", "Ctrl+C")) {}
            if (ImGui::MenuItem("Paste", "Ctrl+V")) {}
            ImGui::Separator();
            if (ImGui::MenuItem("Select All", "Ctrl+A")) {}
            ImGui::EndMenu();
        }
        
        if (ImGui::BeginMenu("Window")) {
            if (ImGui::MenuItem("Hierarchy", nullptr, getPanel("hierarchy") ? &getPanel("hierarchy")->visible : nullptr)) {
                // Toggle panel
            }
            if (ImGui::MenuItem("Inspector", nullptr, getPanel("inspector") ? &getPanel("inspector")->visible : nullptr)) {}
            if (ImGui::MenuItem("Project", nullptr, getPanel("project") ? &getPanel("project")->visible : nullptr)) {}
            if (ImGui::MenuItem("Console", nullptr, getPanel("console") ? &getPanel("console")->visible : nullptr)) {}
            if (ImGui::MenuItem("Scene", nullptr, getPanel("scene") ? &getPanel("scene")->visible : nullptr)) {}
            if (ImGui::MenuItem("Game", nullptr, getPanel("game") ? &getPanel("game")->visible : nullptr)) {}
            ImGui::Separator();
            if (ImGui::MenuItem("Layout")) {}
            ImGui::EndMenu();
        }
        
        if (ImGui::BeginMenu("Tools")) {
            if (ImGui::MenuItem("Scripting")) {}
            if (ImGui::MenuItem("Animation")) {}
            if (ImGui::MenuItem("Physics")) {}
            if (ImGui::MenuItem("Navigation")) {}
            if (ImGui::MenuItem("Lighting")) {}
            if (ImGui::MenuItem("Occlusion Culling")) {}
            ImGui::EndMenu();
        }
        
        if (ImGui::BeginMenu("Help")) {
            if (ImGui::MenuItem("Documentation")) {}
            if (ImGui::MenuItem("About")) {}
            ImGui::EndMenu();
        }
        
        ImGui::EndMainMenuBar();
    }
}

void EditorUI::drawDockspace() {
    ImGuiWindowFlags window_flags = ImGuiWindowFlags_NoDocking | ImGuiWindowFlags_NoTitleBar |
                                   ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoResize |
                                   ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoBringToFrontOnFocus |
                                   ImGuiWindowFlags_NoNavFocus | ImGuiWindowFlags_NoBackground;
    
    const ImGuiViewport* viewport = ImGui::GetMainViewport();
    ImGui::SetNextWindowPos(viewport->Pos);
    ImGui::SetNextWindowSize(viewport->Size);
    ImGui::SetNextWindowViewport(viewport->ID);
    
    ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 0.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowBorderSize, 0.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(0.0f, 0.0f));
    
    ImGui::Begin("DockSpace", nullptr, window_flags);
    ImGui::PopStyleVar(3);
    
    mainDockspaceID = ImGui::GetID("MyDockSpace");
    ImGui::DockSpace(mainDockspaceID, ImVec2(0.0f, 0.0f), ImGuiDockNodeFlags_PassthruCentralNode);
    
    ImGui::End();
}

void EditorUI::drawHierarchyPanel() {
    if (!ImGui::Begin("Hierarchy", nullptr)) {
        ImGui::End();
        return;
    }
    
    if (ImGui::Button("Create Empty")) {
        if (scene) {
            EntityID id = scene->createEntity("Empty GameObject");
            selectedEntity = id;
        }
    }
    ImGui::SameLine();
    if (ImGui::Button("Create Child")) {
        if (scene && selectedEntity != 0) {
            EntityID id = scene->createEntity("Child");
            scene->entityManager.setParent(id, selectedEntity);
        }
    }
    
    ImGui::Separator();
    
    if (scene) {
        drawEntityTree(scene->rootEntity, 0);
    }
    
    ImGui::End();
}

void EditorUI::drawEntityTree(EntityID entity, int depth) {
    if (!scene || !scene->entityManager.isActive(entity)) return;
    
    ImGuiTreeNodeFlags flags = ImGuiTreeNodeFlags_OpenOnArrow | ImGuiTreeNodeFlags_OpenOnDoubleClick |
                              ImGuiTreeNodeFlags_SpanAvailWidth;
    
    if (selectedEntity == entity) flags |= ImGuiTreeNodeFlags_Selected;
    if (scene->entityManager.getChildren(entity).empty()) flags |= ImGuiTreeNodeFlags_Leaf;
    
    const std::string& name = scene->entityManager.getName(entity);
    bool nodeOpen = ImGui::TreeNodeEx((void*)(intptr_t)entity, flags, "%s", name.c_str());
    
    if (ImGui::IsItemClicked()) {
        selectedEntity = entity;
    }
    
    if (ImGui::BeginPopupContextItem()) {
        if (ImGui::MenuItem("Delete")) {
            scene->destroyEntity(entity);
            if (selectedEntity == entity) selectedEntity = 0;
        }
        if (ImGui::MenuItem("Rename")) {
            // Show rename dialog
        }
        if (ImGui::MenuItem("Duplicate")) {
            // Duplicate entity
        }
        ImGui::EndPopup();
    }
    
    if (nodeOpen) {
        const auto& children = scene->entityManager.getChildren(entity);
        for (EntityID child : children) {
            drawEntityTree(child, depth + 1);
        }
        ImGui::TreePop();
    }
}

void EditorUI::drawInspectorPanel() {
    if (!ImGui::Begin("Inspector", nullptr)) {
        ImGui::End();
        return;
    }
    
    if (selectedEntity == 0 || !scene) {
        ImGui::Text("No object selected");
        ImGui::End();
        return;
    }
    
    // Entity header
    ImGui::Text("Entity: %llu", selectedEntity);
    ImGui::SameLine();
    if (ImGui::Button("Delete Entity")) {
        scene->destroyEntity(selectedEntity);
        selectedEntity = 0;
    }
    
    ImGui::Separator();
    
    // Name input
    std::string name = scene->entityManager.getName(selectedEntity);
    char nameBuf[256];
    strncpy(nameBuf, name.c_str(), sizeof(nameBuf) - 1);
    nameBuf[sizeof(nameBuf) - 1] = '\0';
    if (ImGui::InputText("Name", nameBuf, sizeof(nameBuf))) {
        scene->entityManager.setName(selectedEntity, nameBuf);
    }
    
    ImGui::Separator();
    
    // Transform component
    if (ImGui::TreeNodeEx("Transform", ImGuiTreeNodeFlags_DefaultOpen)) {
        auto* transform = scene->componentManager.getComponent<TransformComponent>(selectedEntity);
        if (transform) {
            ImGui::DragFloat3("Position", transform->position, 0.1f);
            ImGui::DragFloat3("Rotation", transform->rotation, 0.1f);
            ImGui::DragFloat3("Scale", transform->scale, 0.01f, 0.001f);
        }
        ImGui::TreePop();
    }
    
    // Add component button
    if (ImGui::Button("Add Component")) {
        ImGui::OpenPopup("AddComponent");
    }
    if (ImGui::BeginPopup("AddComponent")) {
        if (ImGui::MenuItem("Mesh Renderer")) {
            scene->componentManager.addComponent<MeshRendererComponent>(selectedEntity);
        }
        if (ImGui::MenuItem("Camera")) {
            scene->componentManager.addComponent<CameraComponent>(selectedEntity);
        }
        if (ImGui::MenuItem("Light")) {
            scene->componentManager.addComponent<LightComponent>(selectedEntity);
        }
        if (ImGui::MenuItem("Rigidbody")) {
            scene->componentManager.addComponent<RigidBodyComponent>(selectedEntity);
        }
        if (ImGui::MenuItem("Collider")) {
            scene->componentManager.addComponent<ColliderComponent>(selectedEntity);
        }
        if (ImGui::MenuItem("Audio Source")) {
            scene->componentManager.addComponent<AudioSourceComponent>(selectedEntity);
        }
        if (ImGui::MenuItem("Script")) {
            scene->componentManager.addComponent<ScriptComponent>(selectedEntity);
        }
        if (ImGui::MenuItem("Material")) {
            scene->componentManager.addComponent<MaterialComponent>(selectedEntity);
        }
        ImGui::EndPopup();
    }
    
    ImGui::End();
}

void EditorUI::drawProjectPanel() {
    if (!ImGui::Begin("Project", nullptr)) {
        ImGui::End();
        return;
    }
    
    if (ImGui::Button("Import New Asset")) {
        OPENFILENAME ofn = {};
        char szFile[260] = "";
        ofn.lStructSize = sizeof(ofn);
        ofn.hwndOwner = hwnd;
        ofn.lpstrFile = szFile;
        ofn.nMaxFile = sizeof(szFile);
        ofn.lpstrFilter = "All Files\0*.*\0";
        ofn.nFilterIndex = 1;
        ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST | OFN_ALLOWMULTISELECT;
        if (GetOpenFileName(&ofn)) {
            // Import assets
        }
    }
    ImGui::SameLine();
    if (ImGui::Button("Create Folder")) {}
    ImGui::SameLine();
    if (ImGui::Button("Refresh")) {}
    
    ImGui::Separator();
    
    // Asset tree view
    if (ImGui::BeginTable("ProjectTree", 1, ImGuiTableFlags_ScrollY | ImGuiTableFlags_Resizable | ImGuiTableFlags_NoBordersInBody)) {
        ImGui::TableSetupColumn("Assets", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableHeadersRow();
        
        // Show assets from asset database
        // This would iterate over imported assets
        
        ImGui::EndTable();
    }
    
    ImGui::End();
}

void EditorUI::drawConsolePanel() {
    if (!ImGui::Begin("Console", nullptr)) {
        ImGui::End();
        return;
    }
    
    if (ImGui::Button("Clear")) {
        logMessages.clear();
    }
    ImGui::SameLine();
    if (ImGui::Checkbox("Auto Scroll", &autoScrollLog)) {}
    
    ImGui::Separator();
    
    if (ImGui::BeginTable("ConsoleTable", 1, ImGuiTableFlags_ScrollY | ImGuiTableFlags_RowBg | ImGuiTableFlags_NoBordersInBody)) {
        ImGui::TableSetupColumn("Message", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableHeadersRow();
        
        ImGuiListClipper clipper;
        clipper.Begin(logMessages.size());
        while (clipper.Step()) {
            for (int i = clipper.DisplayStart; i < clipper.DisplayEnd; i++) {
                const auto& entry = logMessages[i];
                ImVec4 color = {1, 1, 1, 1};
                switch (entry.level) {
                    case LogLevel::Warning: color = {1, 1, 0, 1}; break;
                    case LogLevel::Error: color = {1, 0, 0, 1}; break;
                    case LogLevel::Success: color = {0, 1, 0, 1}; break;
                    case LogLevel::Debug: color = {0.5f, 0.5f, 1, 1}; break;
                }
                ImGui::TableNextRow();
                ImGui::TableNextColumn();
                ImGui::TextColored(color, "%s", entry.message.c_str());
            }
        }
        clipper.End();
        
        if (autoScrollLog && ImGui::GetScrollY() >= ImGui::GetScrollMaxY() - 1) {
            ImGui::SetScrollHereY(1.0f);
        }
        
        ImGui::EndTable();
    }
    
    ImGui::End();
}

void EditorUI::drawSceneView() {
    if (!ImGui::Begin("Scene", nullptr)) {
        ImGui::End();
        return;
    }
    
    ImVec2 canvasPos = ImGui::GetCursorScreenPos();
    ImVec2 canvasSize = ImGui::GetContentRegionAvail();
    
    if (canvasSize.x > 0 && canvasSize.y > 0) {
        viewportData.position = canvasPos;
        viewportData.size = canvasSize;
        
        ImDrawList* drawList = ImGui::GetWindowDrawList();
        
        // Draw grid
        drawGrid();
        
        // Draw gizmo if entity selected
        if (selectedEntity != 0 && scene && scene->componentManager.hasComponent<TransformComponent>(selectedEntity)) {
            drawGizmo(selectedEntity);
        }
        
        ImGui::InvisibleButton("scene_view", canvasSize);
        if (ImGui::IsItemHovered()) {
            handleViewportInput();
        }
    }
    
    ImGui::End();
}

void EditorUI::drawGameView() {
    if (!ImGui::Begin("Game", nullptr)) {
        ImGui::End();
        return;
    }
    
    ImVec2 canvasSize = ImGui::GetContentRegionAvail();
    
    if (canvasSize.x > 0 && canvasSize.y > 0) {
        ImGui::InvisibleButton("game_view", canvasSize);
        
        if (mode == EditorMode::Play) {
            drawGameView();
        } else {
            ImGui::TextCentered("Game View - Press Play to start");
        }
    }
    
    ImGui::End();
}

void EditorUI::drawAssetBrowser() {
    if (!ImGui::Begin("Asset Browser", nullptr)) {
        ImGui::End();
        return;
    }
    
    // Asset browser implementation
    ImGui::Text("Asset Browser");
    ImGui::Separator();
    
    if (ImGui::BeginTable("AssetBrowserTable", 3, ImGuiTableFlags_ScrollY | ImGuiTableFlags_Resizable)) {
        ImGui::TableSetupColumn("Asset", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableSetupColumn("Type", ImGuiTableColumnFlags_WidthFixed, 100);
        ImGui::TableSetupColumn("Size", ImGuiTableColumnFlags_WidthFixed, 80);
        ImGui::TableHeadersRow();
        
        // List assets from asset database
        // This would iterate over imported assets
        
        ImGui::EndTable();
    }
    
    ImGui::End();
}

void EditorUI::drawAnimationPanel() {
    if (!ImGui::Begin("Animation", nullptr)) {
        ImGui::End();
        return;
    }
    
    ImGui::Text("Animation Editor");
    ImGui::Separator();
    
    if (selectedEntity != 0 && scene) {
        auto* anim = scene->componentManager.getComponent<AnimationComponent>(selectedEntity);
        if (anim) {
            ImGui::DragFloat("Speed", &anim->speed, 0.1f, 0.0f, 10.0f);
            ImGui::Checkbox("Loop", &anim->loop);
            ImGui::Checkbox("Play Automatically", &anim->playAutomatically);
            ImGui::Checkbox("Playing", &anim->playing);
            ImGui::DragFloat("Normalized Time", &anim->normalizedTime, 0.01f, 0.0f, 1.0f);
        }
    }
    
    ImGui::End();
}

void EditorUI::drawProfilerPanel() {
    if (!ImGui::Begin("Profiler", nullptr)) {
        ImGui::End();
        return;
    }
    
    ImGui::Text("FPS: %.1f", fps);
    ImGui::Text("Frame Time: %.2f ms", frameTime * 1000.0f);
    
    // Frame time graph
    static float frameTimes[120] = {};
    static int frameIdx = 0;
    frameTimes[frameIdx++] = frameTime;
    if (frameIdx >= 120) frameIdx = 0;
    
    ImGui::PlotLines("Frame Time", frameTimes, 120, frameIdx, "Frame Time", 0.0f, 0.05f, ImVec2(0, 100));
    
    ImGui::End();
}

void EditorUI::drawConsoleOutput() {
    drawConsolePanel();
}

void EditorUI::drawViewportToolbar() {
    if (ImGui::Begin("Viewport Toolbar", nullptr, ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize)) {
        ImGui::PushItemWidth(100);
        
        // View mode
        static int viewMode = 0;
        if (ImGui::BeginCombo("View", viewMode == 0 ? "Perspective" : "Orthographic")) {
            if (ImGui::Selectable("Perspective")) viewMode = 0;
            if (ImGui::Selectable("Orthographic")) viewMode = 1;
            ImGui::EndCombo();
        }
        ImGui::SameLine();
        
        // Grid options
        ImGui::Checkbox("Show Grid", &viewportData.showGrid);
        ImGui::SameLine();
        ImGui::DragFloat("Grid Size", &viewportData.gridSize, 0.1f, 0.1f, 100.0f);
        
        ImGui::SameLine();
        
        // Camera speed
        ImGui::DragFloat("Camera Speed", &viewportData.cameraSpeed, 0.1f, 0.1f, 100.0f);
        
        ImGui::PopItemWidth();
    }
    ImGui::End();
}

void EditorUI::drawStatusBar() {
    ImGui::Begin("Status Bar", nullptr, ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize |
                                    ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse |
                                    ImGuiWindowFlags_NoFocusOnAppearing | ImGuiWindowFlags_NoNav);
    
    ImGui::Text("FPS: %.1f", fps);
    ImGui::SameLine();
    ImGui::Text("Frame: %.2f ms", frameTime * 1000.0f);
    ImGui::SameLine();
    ImGui::Text("Entity: %llu", selectedEntity);
    ImGui::SameLine();
    ImGui::Text("Mode: %s", mode == EditorMode::Play ? "PLAY" : "EDIT");
    
    ImGui::End();
}

void EditorUI::drawEntityTree(EntityID entity, int depth) {
    // Implemented in drawHierarchyPanel
}

void EditorUI::drawComponentInspector(EntityID entity) {
    // Implemented in drawInspectorPanel
}

void EditorUI::drawAddComponentMenu() {
    // Implemented in drawInspectorPanel
}

void EditorUI::handleInput() {
    // Handle global input
}

void EditorUI::processKeyboardShortcuts() {
    if (ImGui::IsKeyPressed(ImGuiKey_F5)) {
        if (scene) scene->save("kartgib_save.json");
    }
    if (ImGui::IsKeyPressed(ImGuiKey_F9)) {
        if (scene) scene->load("kartgib_save.json");
    }
    if (ImGui::IsKeyPressed(ImGuiKey_F6)) {
        // Record input
    }
    if (ImGui::IsKeyPressed(ImGuiKey_F7)) {
        // Replay input
    }
    if (ImGui::IsKeyPressed(ImGuiKey_F8)) {
        // Toggle debug triangle mode
    }
}

void EditorUI::saveLayout(const std::string& path) {
    ImGui::SaveIniSettingsToDisk(path.c_str());
}

void EditorUI::loadLayout(const std::string& path) {
    ImGui::LoadIniSettingsFromDisk(path.c_str());
}

void EditorUI::drawGrid() {
    ImDrawList* drawList = ImGui::GetWindowDrawList();
    ImVec2 canvasPos = ImGui::GetCursorScreenPos();
    ImVec2 canvasSize = ImGui::GetContentRegionAvail();
    
    float gridSize = viewportData.gridSize * viewportData.zoom;
    ImVec2 origin = ImVec2(canvasPos.x + viewportData.pan.x, canvasPos.y + viewportData.pan.y);
    
    // Draw grid lines
    for (float x = fmodf(origin.x, gridSize); x < canvasSize.x; x += gridSize) {
        drawList->AddLine(ImVec2(canvasPos.x + x, canvasPos.y),
                         ImVec2(canvasPos.x + x, canvasPos.y + canvasSize.y),
                         ImGui::GetColorU32(viewportData.gridColor), 1.0f);
    }
    for (float y = fmodf(origin.y, gridSize); y < canvasSize.y; y += gridSize) {
        drawList->AddLine(ImVec2(canvasPos.x, canvasPos.y + y),
                         ImVec2(canvasPos.x + canvasSize.x, canvasPos.y + y),
                         ImGui::GetColorU32(viewportData.gridColor), 1.0f);
    }
    
    // Draw axes
    drawList->AddLine(ImVec2(canvasPos.x, canvasPos.y + canvasSize.y / 2),
                     ImVec2(canvasPos.x + canvasSize.x, canvasPos.y + canvasSize.y / 2),
                     ImGui::GetColorU32(viewportData.axisColor), 2.0f);
    drawList->AddLine(ImVec2(canvasPos.x + canvasSize.x / 2, canvasPos.y),
                     ImVec2(canvasPos.x + canvasSize.x / 2, canvasPos.y + canvasSize.y),
                     ImVec4(0, 1, 0, 1), 2.0f);
}

void EditorUI::drawGizmo(EntityID entity) {
    if (!scene || !scene->componentManager.hasComponent<TransformComponent>(entity)) return;
    
    auto* transform = scene->componentManager.getComponent<TransformComponent>(entity);
    if (!transform) return;
    
    ImDrawList* drawList = ImGui::GetWindowDrawList();
    ImVec2 canvasPos = ImGui::GetCursorScreenPos();
    ImVec2 canvasSize = ImGui::GetContentRegionAvail();
    
    // Draw gizmo axes
    ImVec2 center(canvasPos.x + canvasSize.x / 2, canvasPos.y + canvasSize.y / 2);
    float gizmoSize = 50.0f * viewportData.zoom;
    
    // X axis (red)
    drawList->AddLine(center, ImVec2(center.x + gizmoSize, center.y), ImGui::GetColorU32({1, 0, 0, 1}), 2.0f);
    // Y axis (green)
    drawList->AddLine(center, ImVec2(center.x, center.y - gizmoSize), ImGui::GetColorU32({0, 1, 0, 1}), 2.0f);
    // Z axis (blue)
    drawList->AddLine(center, ImVec2(center.x - gizmoSize * 0.7f, center.y - gizmoSize * 0.7f), 
                     ImGui::GetColorU32({0, 0, 1, 1}), 2.0f);
}

void EditorUI::drawCameraGizmo(EntityID entity) {
    // Camera frustum gizmo
}

void EditorUI::drawLightGizmo(EntityID entity) {
    // Light gizmo
}

void EditorUI::drawBoundingBox(EntityID entity) {
    // Bounding box visualization
}

void EditorUI::drawCollisionBounds(EntityID entity) {
    // Collision bounds visualization
}

void EditorUI::drawNavigationMesh() {
    // NavMesh visualization
}

void EditorUI::drawSceneGrid() {
    drawGrid();
}

void EditorUI::drawSkybox() {
    // Skybox rendering
}

void EditorUI::drawFog() {
    // Fog rendering
}

void EditorUI::drawPostProcessing() {
    // Post-processing effects
}

void EditorUI::drawBloom() {
    // Bloom effect
}

void EditorUI::drawAmbientOcclusion() {
    // Ambient occlusion
}

void EditorUI::drawShadowMaps() {
    // Shadow map visualization
}

void EditorUI::drawReflectionProbes() {
    // Reflection probe visualization
}

void EditorUI::drawLightProbes() {
    // Light probe visualization
}

void EditorUI::drawNavigationMesh() {
    // Navigation mesh visualization
}

void EditorUI::drawNavigationObstacles() {
    // Navigation obstacle visualization
}

void EditorUI::drawNavigationLinks() {
    // Navigation link visualization
}

void EditorUI::drawOffMeshLinks() {
    // Off-mesh link visualization
}

void EditorUI::drawCloth() {
    // Cloth visualization
}

void EditorUI::drawSoftBody() {
    // Soft body visualization
}

void EditorUI::drawRope() {
    // Rope visualization
}

void EditorUI::drawFluid() {
    // Fluid visualization
}

void EditorUI::drawSmoke() {
    // Smoke visualization
}

void EditorUI::drawFire() {
    // Fire visualization
}

void EditorUI::drawWater() {
    // Water visualization
}

void EditorUI::drawTerrain() {
    // Terrain visualization
}

void EditorUI::drawTree() {
    // Tree visualization
}

void EditorUI::drawGrass() {
    // Grass visualization
}

void EditorUI::drawRock() {
    // Rock visualization
}

void EditorUI::drawBuilding() {
    // Building visualization
}

void EditorUI::drawVehicle() {
    // Vehicle visualization
}

void EditorUI::drawCharacter() {
    // Character visualization
}

void EditorUI::drawProp() {
    // Prop visualization
}

void EditorUI::drawLight() {
    // Light visualization
}

void EditorUI::drawCamera() {
    // Camera visualization
}

void EditorUI::drawAudioSource() {
    // Audio source visualization
}

void EditorUI::drawScript() {
    // Script visualization
}

void EditorUI::drawParticleSystem() {
    // Particle system visualization
}

void EditorUI::drawAudioListener() {
    // Audio listener visualization
}

void EditorUI::drawAudioReverbZone() {
    // Audio reverb zone visualization
}

void EditorUI::drawAudioOcclusionZone() {
    // Audio occlusion zone visualization
}

void EditorUI::drawNavMeshObstacle() {
    // NavMesh obstacle visualization
}

void EditorUI::drawNavMeshSurface() {
    // NavMesh surface visualization
}

void EditorUI::drawNavMeshModifier() {
    // NavMesh modifier visualization
}

void EditorUI::drawNavModifierVolume() {
    // NavModifier volume visualization
}

void EditorUI::drawNavModifierBox() {
    // NavModifier box visualization
}

void EditorUI::drawNavModifierSphere() {
    // NavModifier sphere visualization
}

void EditorUI::drawNavModifierCapsule() {
    // NavModifier capsule visualization
}

void EditorUI::drawNavModifierMesh() {
    // NavModifier mesh visualization
}

void EditorUI::drawNavModifierPlane() {
    // NavModifier plane visualization
}

void EditorUI::drawNavModifierSphereCollider() {
    // NavModifier sphere collider visualization
}

void EditorUI::drawNavModifierBoxCollider() {
    // NavModifier box collider visualization
}

void EditorUI::drawNavModifierCapsuleCollider() {
    // NavModifier capsule collider visualization
}

void EditorUI::drawNavModifierMeshCollider() {
    // NavModifier mesh collider visualization
}

void EditorUI::drawNavModifierPlaneCollider() {
    // NavModifier plane collider visualization
}

void EditorUI::drawLightProbeGroup() {
    // Light probe group visualization
}

void EditorUI::drawReflectionProbe() {
    // Reflection probe visualization
}

void EditorUI::drawLightProbeVolume() {
    // Light probe volume visualization
}

void EditorUI::drawLightProbeProxyVolume() {
    // Light probe proxy volume visualization
}

void EditorUI::drawLightProbeProxyVolume2() {}
void EditorUI::drawLightProbeProxyVolume3() {}
void EditorUI::drawLightProbeProxyVolume4() {}
void EditorUI::drawLightProbeProxyVolume5() {}
void EditorUI::drawLightProbeProxyVolume6() {}
void EditorUI::drawLightProbeProxyVolume7() {}
void EditorUI::drawLightProbeProxyVolume8() {}
void EditorUI::drawLightProbeProxyVolume9() {}
void EditorUI::drawLightProbeProxyVolume10() {}

void EditorUI::drawMaterialPreview(EntityID entity) {
    // Material preview
}

void EditorUI::drawLightSettings(EntityID entity) {
    // Light settings
}

void EditorUI::drawTransformGizmo(EntityID entity) {
    // Transform gizmo
}

} // namespace kartgib::editor