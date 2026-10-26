#pragma once

#include "scene.hpp"
#include <windows.h>
#include <d3d11.h>
#include <d3dcompiler.h>
#include <wrl/client.h>
#include <imgui.h>
#include <imgui_impl_win32.h>
#include <imgui_impl_dx11.h>
#include <vector>
#include <string>
#include <unordered_map>
#include <functional>
#include <variant>
#include <optional>
#include <memory>
#include <chrono>
#include <algorithm>
#include <filesystem>

using Microsoft::WRL::ComPtr;

namespace kartgib::editor {

enum class EditorMode {
    Edit,
    Play,
    Pause
};

enum class LogLevel {
    Info,
    Warning,
    Error,
    Success,
    Debug
};

enum class NotificationType {
    Info,
    Warning,
    Error,
    Success
};

struct EditorConfig {
    int windowWidth = 1920;
    int windowHeight = 1080;
    std::string windowTitle = "KartGib Editor";
    bool vsync = true;
    bool fullscreen = false;
    int msaaSamples = 4;
    std::string layoutFile = "editor_layout.ini";
    std::string theme = "dark";
    float uiScale = 1.0f;
};

struct ViewportData {
    ImVec2 position = {0, 0};
    ImVec2 size = {0, 0};
    float zoom = 1.0f;
    ImVec2 pan = {0, 0};
    bool orthographic = false;
    float orthoSize = 10.0f;
    bool showGrid = true;
    float gridSize = 1.0f;
    int gridSubdivisions = 10;
    ImVec4 gridColor = {0.5f, 0.5f, 0.5f, 0.3f};
    ImVec4 axisColor = {1.0f, 0.0f, 0.0f, 1.0f};
    bool showWireframe = false;
    bool showBounds = false;
    bool showColliders = false;
    bool showNavMesh = false;
    bool showLights = true;
    bool showCamera = true;
    float cameraSpeed = 10.0f;
    float cameraSensitivity = 0.1f;
};

struct DockPanel {
    enum class Type {
        Hierarchy,
        Inspector,
        Project,
        Console,
        Scene,
        Game,
        AssetBrowser,
        Animation,
        Profiler,
        ConsoleOutput,
        Custom
    };

    std::string id;
    std::string title;
    Type type = Type::Custom;
    bool visible = true;
    bool closable = true;
    float minWidth = 200.0f;
    float minHeight = 150.0f;
    ImVec2 defaultPos = {0, 0};
    ImVec2 defaultSize = {300, 400};
    std::function<void()> drawCallback;
};

struct DockPanel {
    enum class Type {
        Hierarchy,
        Inspector,
        Project,
        Console,
        Scene,
        Game,
        AssetBrowser,
        Animation,
        Profiler,
        ConsoleOutput,
        Custom
    };

    std::string id;
    std::string title;
    Type type = Type::Custom;
    bool visible = true;
    bool closable = true;
    float minWidth = 200.0f;
    float minHeight = 150.0f;
    ImVec2 defaultPos = {0, 0};
    ImVec2 defaultSize = {300, 400};
    std::function<void()> drawCallback;
};

class EditorUI {
public:
    EditorConfig config;
    bool running = false;

    HWND hwnd = nullptr;
    HINSTANCE hinstance = nullptr;
    ComPtr<ID3D11Device> d3dDevice;
    ComPtr<ID3D11DeviceContext> d3dContext;
    ComPtr<IDXGISwapChain> swapChain;
    ComPtr<ID3D11RenderTargetView> renderTargetView;
    ComPtr<ID3D11Texture2D> depthStencil;
    ComPtr<ID3D11DepthStencilView> depthStencilView;
    ComPtr<ID3D11DepthStencilState> depthStencilState;
    ComPtr<ID3D11RasterizerState> rasterizerState;
    ComPtr<ID3D11BlendState> blendState;

    ImGuiContext* imguiContext = nullptr;
    ImGuiID mainDockspaceID = 0;

    std::vector<DockPanel> panels;
    ViewportData viewportData;
    ImVec4 clearColor = {0.1f, 0.1f, 0.15f, 1.0f};

    bool showDemoWindow = false;
    bool showStyleEditor = false;
    bool showMetricsWindow = false;
    float frameTime = 0.0f;
    int frameCount = 0;
    float fps = 0.0f;
    bool showFPS = true;
    bool showDebugOverlay = false;

    Scene* scene = nullptr;
    EditorMode mode = EditorMode::Edit;
    uint64_t selectedEntity = 0;
    std::string clipboardContent;

    struct LogEntry {
        std::string message;
        LogLevel level;
        double timestamp;
    };
    std::vector<LogEntry> logMessages;
    int logScrollPos = 0;
    bool autoScrollLog = true;

    struct Notification {
        std::string message;
        NotificationType type;
        float timer = 0.0f;
        float duration = 3.0f;
    };
    std::vector<Notification> notifications;

    // Editor state
    bool isDraggingObject = false;
    uint64_t draggedEntity = 0;
    ImVec2 dragStartMousePos = {0, 0};
    glm::vec3 dragStartPos = {0, 0, 0};
    bool isTransforming = false;
    enum class TransformType { None, Translate, Rotate, Scale } transformType = TransformType::None;
    glm::vec3 transformAxis = {1, 0, 0};
    float transformValue = 0.0f;
    glm::vec3 transformStartValue = {0, 0, 0};
    float transformStartValueFloat = 0.0f;

    // Play mode state
    Scene* playScene = nullptr;
    bool isPlaying = false;
    float playTime = 0.0f;
    float deltaTime = 0.0f;

    // Gizmo state
    bool showGizmo = true;
    bool showGrid = true;
    float gridSize = 1.0f;
    int gridSubdivisions = 10;

public:
    EditorUI(const EditorConfig& config = EditorConfig());
    ~EditorUI();

    bool initialize(HINSTANCE hInstance, int nCmdShow);
    void run();
    void shutdown();

    void setScene(Scene* scene);
    Scene* getScene() const { return scene; }

    void setSelectedEntity(uint64_t entity);
    uint64_t getSelectedEntity() const { return selectedEntity; }

    void setMode(EditorMode mode);
    EditorMode getMode() const { return mode; }

    void addPanel(const DockPanel& panel);
    void removePanel(const std::string& id);
    DockPanel* getPanel(const std::string& id);

    void setViewportData(const ViewportData& data) { viewportData = data; }
    const ViewportData& getViewportData() const { return viewportData; }

    void setClearColor(const ImVec4& color) { clearColor = color; }
    const ImVec4& getClearColor() const { return clearColor; }

    void setTheme(const std::string& theme);
    void applyTheme(const std::string& theme);

    void saveLayout(const std::string& path);
    void loadLayout(const std::string& path);

    void logMessage(const std::string& message, LogLevel level = LogLevel::Info);
    void clearLog();

    void showNotification(const std::string& message, NotificationType type = NotificationType::Info, float duration = 3.0f);

    bool isPlaying() const { return isPlaying; }
    float getPlayTime() const { return playTime; }
    float getDeltaTime() const { return deltaTime; }

private:
    void initializeImGui();
    void shutdownImGui();
    void newFrame();
    void endFrame();
    void render();

    void drawMainMenuBar();
    void drawDockspace();
    void drawHierarchyPanel();
    void drawInspectorPanel();
    void drawProjectPanel();
    void drawConsolePanel();
    void drawSceneView();
    void drawGameView();
    void drawAssetBrowser();
    void drawAnimationPanel();
    void drawProfilerPanel();
    void drawConsoleOutput();
    void drawViewportToolbar();
    void drawStatusBar();

    void drawEntityTree(EntityID entity, int depth);
    void drawComponentInspector(EntityID entity);
    void drawAddComponentMenu();

    void handleInput();
    void processKeyboardShortcuts();

    void saveLayout(const std::string& path);
    void loadLayout(const std::string& path);

    void updateFPS(float deltaTime);

    struct ThemeColors {
        ImVec4 windowBg = ImVec4(0.13f, 0.13f, 0.15f, 1.0f);
        ImVec4 headerBg = ImVec4(0.2f, 0.2f, 0.22f, 1.0f);
        ImVec4 headerHover = ImVec4(0.3f, 0.3f, 0.32f, 1.0f);
        ImVec4 headerActive = ImVec4(0.4f, 0.4f, 0.42f, 1.0f);
        ImVec4 button = ImVec4(0.25f, 0.25f, 0.27f, 1.0f);
        ImVec4 buttonHover = ImVec4(0.35f, 0.35f, 0.37f, 1.0f);
        ImVec4 buttonActive = ImVec4(0.4f, 0.4f, 0.42f, 1.0f);
        ImVec4 frameBg = ImVec4(0.18f, 0.18f, 0.2f, 1.0f);
        ImVec4 frameBgHover = ImVec4(0.25f, 0.25f, 0.27f, 1.0f);
        ImVec4 frameBgActive = ImVec4(0.3f, 0.3f, 0.32f, 1.0f);
        ImVec4 titleBg = ImVec4(0.16f, 0.16f, 0.18f, 1.0f);
        ImVec4 titleBgActive = ImVec4(0.2f, 0.2f, 0.22f, 1.0f);
        ImVec4 titleBgCollapsed = ImVec4(0.13f, 0.13f, 0.15f, 1.0f);
        ImVec4 border = ImVec4(0.3f, 0.3f, 0.32f, 1.0f);
        ImVec4 borderShadow = ImVec4(0.0f, 0.0f, 0.0f, 0.0f);
        ImVec4 text = ImVec4(0.9f, 0.9f, 0.9f, 1.0f);
        ImVec4 textDisabled = ImVec4(0.5f, 0.5f, 0.5f, 1.0f);
        ImVec4 checkMark = ImVec4(0.8f, 0.6f, 0.2f, 1.0f);
        ImVec4 sliderGrab = ImVec4(0.8f, 0.6f, 0.2f, 1.0f);
        ImVec4 sliderGrabActive = ImVec4(0.9f, 0.7f, 0.3f, 1.0f);
        ImVec4 header = ImVec4(0.25f, 0.25f, 0.27f, 1.0f);
        ImVec4 headerHover = ImVec4(0.35f, 0.35f, 0.37f, 1.0f);
        ImVec4 headerActive = ImVec4(0.4f, 0.4f, 0.42f, 1.0f);
        ImVec4 separator = ImVec4(0.3f, 0.3f, 0.32f, 1.0f);
        ImVec4 separatorHover = ImVec4(0.4f, 0.4f, 0.42f, 1.0f);
        ImVec4 separatorActive = ImVec4(0.5f, 0.5f, 0.52f, 1.0f);
        ImVec4 resizeGrip = ImVec4(0.8f, 0.6f, 0.2f, 1.0f);
        ImVec4 resizeGripHover = ImVec4(0.9f, 0.7f, 0.3f, 1.0f);
        ImVec4 resizeGripActive = ImVec4(1.0f, 0.8f, 0.4f, 1.0f);
        ImVec4 tab = ImVec4(0.18f, 0.18f, 0.2f, 1.0f);
        ImVec4 tabHover = ImVec4(0.25f, 0.25f, 0.27f, 1.0f);
        ImVec4 tabActive = ImVec4(0.3f, 0.3f, 0.32f, 1.0f);
        ImVec4 tabUnfocused = ImVec4(0.13f, 0.13f, 0.15f, 1.0f);
        ImVec4 tabUnfocusedActive = ImVec4(0.2f, 0.2f, 0.22f, 1.0f);
        ImVec4 plotLines = ImVec4(0.8f, 0.6f, 0.2f, 1.0f);
        ImVec4 plotLinesHover = ImVec4(0.9f, 0.7f, 0.3f, 1.0f);
        ImVec4 plotHistogram = ImVec4(0.9f, 0.7f, 0.3f, 1.0f);
        ImVec4 plotHistogramHover = ImVec4(1.0f, 0.8f, 0.4f, 1.0f);
        ImVec4 tableHeaderBg = ImVec4(0.18f, 0.18f, 0.2f, 1.0f);
        ImVec4 tableBorderStrong = ImVec4(0.3f, 0.3f, 0.32f, 1.0f);
        ImVec4 tableBorderLight = ImVec4(0.2f, 0.2f, 0.22f, 1.0f);
        ImVec4 tableRowBg = ImVec4(0.13f, 0.13f, 0.15f, 1.0f);
        ImVec4 tableRowBgAlt = ImVec4(0.16f, 0.16f, 0.18f, 1.0f);
        ImVec4 textSelectedBg = ImVec4(0.8f, 0.6f, 0.2f, 1.0f);
        ImVec4 dragDropTarget = ImVec4(1.0f, 1.0f, 0.0f, 0.9f);
        ImVec4 navHighlight = ImVec4(0.8f, 0.6f, 0.2f, 1.0f);
        ImVec4 navWindowingHighlight = ImVec4(1.0f, 1.0f, 1.0f, 0.7f);
        ImVec4 navWindowingDimBg = ImVec4(0.8f, 0.8f, 0.8f, 0.2f);
        ImVec4 modalWindowDimBg = ImVec4(0.8f, 0.8f, 0.8f, 0.35f);
    };

    ThemeColors darkTheme;
    ThemeColors lightTheme;
    ThemeColors* currentTheme = &darkTheme;

    bool initialized = false;

    void applyThemeColors(const ThemeColors& theme);
    void renderNotifications();
    void updateNotifications(float deltaTime);
    void drawGrid();
    void drawGizmo(EntityID entity);
    void drawPlayControls();
    void drawDebugInfo();
    void handleViewportInput();
    void handleHierarchyInput();
    void handleInspectorInput();
    void drawMaterialPreview(EntityID entity);
    void drawLightSettings(EntityID entity);
    void drawTransformGizmo(EntityID entity);
    void drawCameraGizmo(EntityID entity);
    void drawLightGizmo(EntityID entity);
    void drawBoundingBox(EntityID entity);
    void drawCollisionBounds(EntityID entity);
    void drawNavigationMesh();
    void drawSceneGrid();
    void drawSkybox();
    void drawFog();
    void drawPostProcessing();
    void drawBloom();
    void drawAmbientOcclusion();
    void drawShadowMaps();
    void drawReflectionProbes();
    void drawLightProbes();
    void drawNavigationObstacles();
    void drawNavigationLinks();
    void drawOffMeshLinks();
    void drawCloth();
    void drawSoftBody();
    void drawRope();
    void drawFluid();
    void drawSmoke();
    void drawFire();
    void drawWater();
    void drawTerrain();
    void drawTree();
    void drawGrass();
    void drawRock();
    void drawBuilding();
    void drawVehicle();
    void drawCharacter();
    void drawProp();
    void drawLight();
    void drawCamera();
    void drawAudioSource();
    void drawScript();
    void drawParticleSystem();
    void drawAudioListener();
    void drawAudioReverbZone();
    void drawAudioOcclusionZone();
    void drawNavMeshObstacle();
    void drawNavMeshSurface();
    void drawNavMeshModifier();
    void drawNavModifierVolume();
    void drawNavModifierBox();
    void drawNavModifierSphere();
    void drawNavModifierCapsule();
    void drawNavModifierMesh();
    void drawNavModifierPlane();
    void drawNavModifierSphereCollider();
    void drawNavModifierBoxCollider();
    void drawNavModifierCapsuleCollider();
    void drawNavModifierMeshCollider();
    void drawNavModifierPlaneCollider();
    void drawNavModifierSphereCollider();
    void drawNavModifierBoxCollider();
    void drawNavModifierCapsuleCollider();
    void drawNavModifierMeshCollider();
    void drawNavModifierPlaneCollider();
    void drawLightProbeGroup();
    void drawReflectionProbe();
    void drawLightProbeVolume();
    void drawLightProbeProxyVolume();
    void drawLightProbeProxyVolume2();
    void drawLightProbeProxyVolume3();
    void drawLightProbeProxyVolume4();
    void drawLightProbeProxyVolume5();
    void drawLightProbeProxyVolume6();
    void drawLightProbeProxyVolume7();
    void drawLightProbeProxyVolume8();
    void drawLightProbeProxyVolume9();
    void drawLightProbeProxyVolume10();
};

} // namespace kartgib::editor