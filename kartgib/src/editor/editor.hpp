#pragma once

#include "editor/editor_ui.hpp"
#include "editor/scene.hpp"
#include "editor/scene_serializer.hpp"
#include "editor/asset_pipeline.hpp"
#include "editor/material.hpp"
#include "editor/animation.hpp"

#include <string>
#include <memory>
#include <chrono>

namespace kartgib::editor {

class KartGibEditor {
public:
    KartGibEditor();
    ~KartGibEditor();

    bool initialize(HINSTANCE hInstance, int nCmdShow);
    int run();
    void shutdown();

    // Scene management
    Scene& getScene() { return scene_; }
    void setScene(std::unique_ptr<Scene> scene);
    
    // Asset database
    AssetDatabase& getAssetDatabase() { return assetDatabase_; }
    
    // Editor UI
    EditorUI& getEditorUI() { return editorUI_; }
    
    // Editor state
    bool isRunning() const { return running_; }
    EditorMode getEditorMode() const { return editorUI_.getMode(); }
    
    // File operations
    bool newScene();
    bool openScene(const std::string& path);
    bool saveScene(const std::string& path);
    bool saveSceneAs(const std::string& path);
    
    // Asset operations
    std::string importAsset(const std::string& path, const ImportSettings& settings = {});
    std::future<AssetImportResult> importAssetAsync(const std::string& path, const ImportSettings& settings = {}, int priority = 0);
    
    // Play mode
    void startPlayMode();
    void stopPlayMode();
    void pausePlayMode();
    void resumePlayMode();
    
    // Editor settings
    void setTheme(const std::string& theme);
    const std::string& getTheme() const { return config_.windowTitle; }
    
private:
    EditorConfig config_;
    EditorUI editorUI_;
    Scene scene_;
    AssetDatabase assetDatabase_;
    bool running_ = false;
    bool isPlaying_ = false;
    float playTime_ = 0.0f;
    
    // Initialize subsystems
    bool initializeEditor();
    bool initializeAssetDatabase();
    bool initializeScene();
    
    // Main loop
    void update(float deltaTime);
    void render();
    
    // Play mode management
    void updatePlayMode(float deltaTime);
    void stopPlayModeInternal();
};

} // namespace kartgib::editor