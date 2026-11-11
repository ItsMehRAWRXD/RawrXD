#pragma once

#include <string>
#include <vector>
#include <unordered_map>
#include <memory>
#include <filesystem>
#include <optional>
#include <variant>
#include <functional>
#include <future>
#include <mutex>
#include <queue>
#include <thread>
#include <atomic>
#include <cstdint>
#include <string_view>

namespace kartgib::editor {

enum class AssetType : uint8_t {
    Unknown = 0,
    Model = 1,          // FBX, OBJ, glTF
    Texture = 2,        // PNG, JPG, TGA, BMP, HDR, EXR, DDS, KTX
    Audio = 3,          // WAV, OGG, MP3, FLAC
    Shader = 4,         // SPIR-V, HLSL, GLSL
    Material = 5,
    Prefab = 6,
    Scene = 7,
    Animation = 8,
    AudioClip = 9,
    Font = 10,
    Script = 11,
    ComputeShader = 12,
    ParticleSystem = 13,
    NavMesh = 14,
    PhysicsMaterial = 15,
    FontAtlas = 16,
    Cubemap = 17,
    RenderTexture = 16,
    Video = 17
};

enum class ImportStatus : uint8_t {
    Pending = 0,
    Queued = 1,
    Processing = 2,
    Completed = 3,
    Failed = 4,
    Cancelled = 5
};

struct AssetMetadata {
    std::string guid;
    std::string originalPath;
    std::string importPath;
    AssetType type = AssetType::Unknown;
    ImportStatus status = ImportStatus::Pending;
    uint64_t fileSize = 0;
    uint64_t importTime = 0;
    uint64_t lastModified = 0;
    std::string hash; // SHA-256
    std::string importerVersion;
    std::unordered_map<std::string, std::string> metadata;
    std::vector<std::string> dependencies; // GUIDs of dependencies
    std::vector<std::string> dependents;   // GUIDs of assets that depend on this
    bool isReadOnly = false;
    bool isHidden = false;
    std::string tags;
};

struct ImportSettings {
    // Model import
    float globalScale = 1.0f;
    bool convertUnits = true;
    float unitScale = 1.0f;
    bool importMaterials = true;
    bool importAnimations = true;
    bool importCameras = false;
    bool importLights = false;
    bool generateColliders = false;
    float colliderConvexHullMaxVerts = 256;
    bool optimizeMesh = true;
    bool weldVertices = true;
    float weldDistance = 0.0001f;
    bool generateTangents = true;
    bool calculateNormals = true;
    float normalSmoothingAngle = 60.0f;
    bool splitTangents = false;
    bool swapUVChannels = false;
    bool flipUVs = false;
    bool flipWinding = false;
    bool flipNormals = false;
    bool keepQuads = false;
    bool importBlendShapes = true;
    bool importVisibility = true;
    bool importBlendShapeNormals = true;
    bool optimizeGameObjects = true;
    float meshCompressionRatio = 0.5f;
    bool readWriteEnabled = false;
    bool optimizeIndexBuffer = true;
    bool keepUnusedVertices = false;
    
    // Animation
    float animationCompression = 0.5f;
    bool loopTime = false;
    bool loopPose = false;
    float animationCompressionError = 0.5f;
    
    // Texture
    enum class TextureType { Default, NormalMap, Lightmap, SingleChannel, Cursor, Cookie, Sprite } textureType = TextureType::Default;
    enum class TextureShape { Texture2D, Texture3D, Cube, CubeArray } textureShape = TextureShape::Texture2D;
    int maxTextureSize = 2048;
    bool generateMipMaps = true;
    int mipMapFilter = 0; // 0=Box, 1=Kaiser, 2=Custom
    int mipMapFadeDistanceStart = 1;
    int mipMapFadeDistanceEnd = 3;
    bool borderMipMaps = false;
    bool mipMapsPreserveCoverage = false;
    float alphaTestReferenceValue = 0.5f;
    bool alphaIsTransparency = false;
    enum class WrapMode { Repeat, Clamp, Mirror, MirrorOnce } wrapModeU = WrapMode::Repeat, wrapModeV = WrapMode::Repeat, wrapModeW = WrapMode::Repeat;
    enum class FilterMode { Point, Bilinear, Trilinear } filterMode = FilterMode::Trilinear;
    int anisoLevel = 1;
    float mipMapBias = 0.0f;
    bool sRGBTexture = true;
    bool normalMap = false;
    bool convertToNormalMap = false;
    float normalMapFilter = 1.0f;
    bool alphaIsAlpha = false;
    bool alphaSource = 0; // 0=FromGray, 1=FromRGB, 2=FromAlpha
    bool flipVertically = false;
    bool isReadable = false;
    bool streamingMipmaps = false;
    int streamingMipmapsPriority = 0;
    
    // Audio
    enum class AudioCompressionFormat { PCM, Vorbis, ADPCM, MP3 } audioFormat = AudioCompressionFormat::Vorbis;
    enum class AudioLoadType { DecompressOnLoad, CompressedInMemory, Streaming } loadType = AudioLoadType::DecompressOnLoad;
    float audioQuality = 0.5f;
    bool audio3D = false;
    bool preloadAudioData = true;
    
    // Model
    enum class ModelScaleFactor { File = 0, Custom = 1 } modelScaleFactor = ModelScaleFactor::File;
    float customScaleFactor = 1.0f;
    bool importBlendShapes = true;
    bool importVisibility = true;
    bool importBlendShapeNormals = true;
    bool importCameras = false;
    bool importLights = false;
    bool optimizeGameObjects = true;
    bool importAnimation = true;
    float animationCompression = 0.5f;
    bool loopTime = false;
    bool loopPose = false;
    float animationCompressionError = 0.5f;
};

struct AssetImportResult {
    bool success = false;
    std::string errorMessage;
    std::string assetGUID;
    std::vector<std::string> createdAssetGUIDs;
    std::vector<std::string> warnings;
    uint64_t importTimeMs = 0;
    uint64_t fileSize = 0;
    uint64_t outputSize = 0;
};

class AssetImporter {
public:
    virtual ~AssetImporter() = default;
    virtual AssetType getSupportedType() const = 0;
    virtual std::vector<std::string> getSupportedExtensions() const = 0;
    virtual bool canImport(const std::string& path) const = 0;
    virtual AssetImportResult import(const std::string& path, const ImportSettings& settings, const std::string& outputDir) = 0;
    virtual bool canHandleMultiThreaded() const { return true; }
    virtual void cancel() {}
};

class ModelImporter : public AssetImporter {
public:
    AssetType getSupportedType() const override { return AssetType::Model; }
    std::vector<std::string> getSupportedExtensions() const override {
        return {".fbx", ".obj", ".gltf", ".glb", ".dae", ".blend", ".3ds", ".ase", ".dxf", ".lwo", ".lxo", ".ply", ".stl", ".x", ".ac", ".ms3d", ".cob", ".scn", ".xml", ".irr", ".mdl", ".md2", ".md3", ".pk3", ".mdc", ".md5mesh", ".md5anim", ".smd", ".vta", ".dmx", ".qc", ".qci", ".mdl", ".smd", ".vta", ".dmx"};
    }
    bool canImport(const std::string& path) const override {
        std::string ext = std::filesystem::path(path).extension().string();
        std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);
        for (const auto& ext2 : getSupportedExtensions()) {
            if (ext == ext2) return true;
        }
        return false;
    }
    AssetImportResult import(const std::string& path, const ImportSettings& settings, const std::string& outputDir) override;
};

class TextureImporter : public AssetImporter {
public:
    AssetType getSupportedType() const override { return AssetType::Texture; }
    std::vector<std::string> getSupportedExtensions() const override {
        return {".png", ".jpg", ".jpeg", ".tga", ".bmp", ".psd", ".gif", ".hdr", ".exr", ".dds", ".ktx", ".pvr", ".pvr.gz", ".astc", ".tif", ".tiff", ".webp", ".jxl"};
    }
    bool canImport(const std::string& path) const override {
        std::string ext = std::filesystem::path(path).extension().string();
        std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);
        for (const auto& ext2 : getSupportedExtensions()) {
            if (ext == ext2) return true;
        }
        return false;
    }
    AssetImportResult import(const std::string& path, const ImportSettings& settings, const std::string& outputDir) override;
};

class AudioImporter : public AssetImporter {
public:
    AssetType getSupportedType() const override { return AssetType::Audio; }
    std::vector<std::string> getSupportedExtensions() const override {
        return {".wav", ".mp3", ".ogg", ".flac", ".aiff", ".aif", ".au", ".raw", ".snd", ".voc", ".mod", ".it", ".xm", ".s3m", ".midi", ".mid", ".kar", ".rmi"};
    }
    bool canImport(const std::string& path) const override {
        std::string ext = std::filesystem::path(path).extension().string();
        std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);
        for (const auto& ext2 : getSupportedExtensions()) {
            if (ext == ext2) return true;
        }
        return false;
    }
    AssetImportResult import(const std::string& path, const ImportSettings& settings, const std::string& outputDir) override;
};

class AssetDatabase {
    std::unordered_map<std::string, AssetMetadata> assets_;
    std::unordered_map<std::string, std::string> pathToGUID_;
    std::unordered_map<std::string, std::unique_ptr<AssetImporter>> importers_;
    std::string assetRoot_;
    std::string libraryPath_;
    std::mutex mutex_;
    std::atomic<bool> scanning_ = false;
    std::atomic<uint64_t> nextGUIDCounter_ = 1;
    
    // Import queue
    struct ImportJob {
        std::string path;
        ImportSettings settings;
        std::promise<AssetImportResult> promise;
        std::chrono::steady_clock::time_point queuedTime;
        int priority = 0;
    };
    
    std::queue<ImportJob> importQueue_;
    std::mutex queueMutex_;
    std::condition_variable queueCV_;
    std::vector<std::thread> importThreads_;
    std::atomic<bool> stopImportThreads_ = false;
    std::atomic<int> activeImports_ = 0;
    const int maxConcurrentImports_ = 4;
    
    // Asset callbacks
    std::function<void(const std::string&)> onAssetImported;
    std::function<void(const std::string&, const std::string&)> onAssetChanged;
    std::function<void(const std::string&)> onAssetDeleted;
    std::function<void(const std::string&, const std::string&)> onAssetMoved;
    
    std::string generateGUID();
    void registerDefaultImporters();
    void processImportQueue();
    void importThreadWorker();
    AssetImportResult processImport(AssetImporter* importer, const std::string& path, const ImportSettings& settings);
    void writeMetadata(const AssetMetadata& metadata);
    AssetMetadata readMetadata(const std::string& guid);
    void scanAssetDirectory(const std::filesystem::path& dir);
    void processFile(const std::filesystem::path& file);
    void updateDependencies(const std::string& guid, const std::vector<std::string>& newDeps);
    
public:
    AssetDatabase(const std::string& assetRoot, const std::string& libraryPath);
    ~AssetDatabase();
    
    void initialize();
    void shutdown();
    
    void scanAssets();
    void refresh();
    
    std::optional<AssetMetadata> getAsset(const std::string& guid) const;
    std::optional<AssetMetadata> getAssetByPath(const std::string& path) const;
    std::vector<AssetMetadata> getAssetsByType(AssetType type) const;
    std::vector<std::string> findAssets(const std::string& pattern, AssetType type = AssetType::Unknown) const;
    
    std::string importAsset(const std::string& path, const ImportSettings& settings = {});
    std::future<AssetImportResult> importAssetAsync(const std::string& path, const ImportSettings& settings = {}, int priority = 0);
    
    void deleteAsset(const std::string& guid);
    void moveAsset(const std::string& guid, const std::string& newPath);
    void renameAsset(const std::string& guid, const std::string& newName);
    
    void setAssetReadOnly(const std::string& guid, bool readOnly);
    void setAssetHidden(const std::string& guid, bool hidden);
    void setAssetTags(const std::string& guid, const std::string& tags);
    
    void addDependency(const std::string& guid, const std::string& dependencyGUID);
    void removeDependency(const std::string& guid, const std::string& dependencyGUID);
    std::vector<std::string> getDependencies(const std::string& guid) const;
    std::vector<std::string> getDependents(const std::string& guid) const;
    
    void refreshAsset(const std::string& guid);
    void refreshAll();
    
    void setOnAssetImported(std::function<void(const std::string&)> callback) { onAssetImported = callback; }
    void setOnAssetChanged(std::function<void(const std::string&, const std::string&)> callback) { onAssetChanged = callback; }
    void setOnAssetDeleted(std::function<void(const std::string&)> callback) { onAssetDeleted = callback; }
    void setOnAssetMoved(std::function<void(const std::string&, const std::string&)> callback) { onAssetMoved = callback; }
    
    const std::string& getAssetRoot() const { return assetRoot_; }
    const std::string& getLibraryPath() const { return libraryPath_; }
    size_t getAssetCount() const { return assets_.size(); }
    size_t getImportQueueSize() const { return importQueue_.size(); }
    int getActiveImports() const { return activeImports_; }
    
    void setMaxConcurrentImports(int count) { 
        if (count > 0) maxConcurrentImports_ = count; 
    }
};

} // namespace kartgib::editor