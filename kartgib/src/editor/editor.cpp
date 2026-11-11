#include "editor.hpp"

namespace kartgib::editor {

KartGibEditor::KartGibEditor() : editorUI_(config_) {}

KartGibEditor::~KartGibEditor() {
    shutdown();
}

bool KartGibEditor::initialize(HINSTANCE hInstance, int nCmdShow) {
    if (!initializeEditor()) return false;
    if (!initializeAssetDatabase()) return false;
    if (!initializeScene()) return false;
    
    return editorUI_.initialize(hInstance, nCmdShow);
}

int KartGibEditor::run() {
    running_ = true;
    
    // Main editor loop
    editorUI_.run();
    
    running_ = false;
    return 0;
}

void KartGibEditor::shutdown() {
    stopPlayModeInternal();
    editorUI_.shutdown();
    assetDatabase_.shutdown();
}

bool KartGibEditor::initializeEditor() {
    // Editor is initialized in constructor
    return true;
}

bool KartGibEditor::initializeAssetDatabase() {
    std::filesystem::path assetRoot = std::filesystem::current_path() / "Assets";
    std::filesystem::path libraryPath = std::filesystem::current_path() / "Library";
    
    // Re-initialize with proper paths
    // Note: AssetDatabase is already constructed, we need to reinitialize
    // For now, just scan assets
    assetDatabase_.scanAssets();
    return true;
}

bool KartGibEditor::initializeScene() {
    scene_ = Scene();
    scene_.name = "Untitled Scene";
    
    // Create default entities
    EntityID mainCamera = scene_.createEntity("Main Camera");
    scene_.entityManager.setParent(mainCamera, scene_.rootEntity);
    scene_.componentManager.addComponent<TransformComponent>(mainCamera);
    auto& camera = scene_.componentManager.addComponent<CameraComponent>(mainCamera);
    camera.isMain = true;
    camera.fov = 60.0f;
    camera.nearPlane = 0.1f;
    camera.farPlane = 1000.0f;
    scene_.entityManager.getComponent<TransformComponent>(mainCamera).position[2] = -10.0f;
    
    EntityID directionalLight = scene_.createEntity("Directional Light");
    scene_.entityManager.setParent(directionalLight, scene_.rootEntity);
    scene_.componentManager.addComponent<TransformComponent>(directionalLight);
    auto& light = scene_.componentManager.addComponent<LightComponent>(directionalLight);
    light.type = LightComponent::Type::Directional;
    light.intensity = 1.0f;
    scene_.entityManager.getComponent<TransformComponent>(directionalLight).rotation[0] = 0.5f;
    
    EntityID cube = scene_.createEntity("Cube");
    scene_.entityManager.setParent(cube, scene_.rootEntity);
    scene_.componentManager.addComponent<TransformComponent>(cube);
    scene_.entityManager.getComponent<TransformComponent>(cube).position[1] = 1.0f;
    scene_.componentManager.addComponent<MeshRendererComponent>(cube);
    scene_.componentManager.addComponent<MeshComponent>(cube);
    scene_.componentManager.addComponent<MaterialComponent>(cube);
    
    editorUI_.setScene(&scene_);
    return true;
}

void KartGibEditor::setScene(std::unique_ptr<Scene> scene) {
    scene_ = *scene;
    editorUI_.setScene(&scene_);
}

bool KartGibEditor::newScene() {
    stopPlayModeInternal();
    scene_ = Scene();
    scene_.name = "Untitled Scene";
    scene_.path = "";
    editorUI_.setScene(&scene_);
    return true;
}

bool KartGibEditor::openScene(const std::string& path) {
    stopPlayModeInternal();
    scene_ = Scene();
    if (scene_.load(path)) {
        scene_.path = path;
        editorUI_.setScene(&scene_);
        return true;
    }
    return false;
}

bool KartGibEditor::saveScene(const std::string& path) {
    if (scene_.save(path)) {
        scene_.path = path;
        return true;
    }
    return false;
}

bool KartGibEditor::saveSceneAs(const std::string& path) {
    return saveScene(path);
}

std::string KartGibEditor::importAsset(const std::string& path, const ImportSettings& settings) {
    return assetDatabase_.importAsset(path, settings);
}

std::future<AssetImportResult> KartGibEditor::importAssetAsync(const std::string& path, const ImportSettings& settings, int priority) {
    return assetDatabase_.importAssetAsync(path, settings, priority);
}

void KartGibEditor::startPlayMode() {
    if (!isPlaying_) {
        isPlaying_ = true;
        playTime_ = 0.0f;
        editorUI_.setMode(EditorMode::Play);
        
        // Clone scene for play mode
        // In a real implementation, we'd deep copy the scene
    }
}

void KartGibEditor::stopPlayMode() {
    stopPlayModeInternal();
}

void KartGibEditor::pausePlayMode() {
    if (isPlaying_) {
        editorUI_.setMode(EditorMode::Pause);
    }
}

void KartGibEditor::resumePlayMode() {
    if (isPlaying_) {
        editorUI_.setMode(EditorMode::Play);
    }
}

void KartGibEditor::setTheme(const std::string& theme) {
    editorUI_.setTheme(theme);
}

bool KartGibEditor::initializeEditor() {
    return true;
}

void KartGibEditor::update(float deltaTime) {
    if (isPlaying_) {
        updatePlayMode(deltaTime);
        playTime_ += deltaTime;
    }
}

void KartGibEditor::render() {
    editorUI_.render();
}

void KartGibEditor::updatePlayMode(float deltaTime) {
    // Update game logic during play mode
    // This would update all active scenes, physics, AI, etc.
}

void KartGibEditor::stopPlayModeInternal() {
    if (isPlaying_) {
        isPlaying_ = false;
        playTime_ = 0.0f;
        editorUI_.setMode(EditorMode::Edit);
        
        // Restore scene from edit state
        // In a real implementation, we'd restore from backup
    }
}

} // namespace kartgib::editor