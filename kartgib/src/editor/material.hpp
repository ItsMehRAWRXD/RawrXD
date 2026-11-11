#pragma once

#include <string>
#include <vector>
#include <unordered_map>
#include <variant>
#include <optional>
#include <filesystem>
#include <memory>
#include <string_view>
#include <cstdint>
#include <array>
#include <glm/glm.hpp>

namespace kartgib::editor {

using ShaderPropertyType = enum {
    Float = 0,
    Float2 = 1,
    Float3 = 2,
    Float4 = 3,
    Int = 4,
    Int2 = 5,
    Int3 = 6,
    Int4 = 7,
    Bool = 8,
    Texture2D = 9,
    Texture3D = 10,
    Cubemap = 11,
    Buffer = 12,
    StructuredBuffer = 13,
    RWTexture2D = 14,
    RWTexture3D = 15,
    RWBuffer = 16,
    Sampler = 17
};

struct ShaderProperty {
    std::string name;
    ShaderPropertyType type;
    uint32_t binding = 0;
    uint32_t set = 0;
    uint32_t offset = 0;
    uint32_t size = 0;
    std::vector<uint8_t> defaultValue;
    std::string displayName;
    std::string tooltip;
    bool isHidden = false;
    bool isReadOnly = false;
    float minValue = 0.0f;
    float maxValue = 1.0f;
};

struct ShaderPass {
    std::string name;
    std::string vertexShader;
    std::string fragmentShader;
    std::string geometryShader;
    std::string tessControlShader;
    std::string tessEvaluationShader;
    std::string computeShader;
    std::string rayGenShader;
    std::string rayMissShader;
    std::string rayHitShader;
    std::string rayCallableShader;
    
    // Render states
    struct RenderState {
        bool depthTest = true;
        enum class DepthFunc { Never, Less, Equal, LEqual, Greater, NotEqual, GEqual, Always } depthFunc = DepthFunc::LEqual;
        bool depthWrite = true;
        bool depthClamp = false;
        bool depthBiasEnable = false;
        float depthBiasConstant = 0.0f;
        float depthBiasClamp = 0.0f;
        float depthBiasSlope = 0.0f;
        
        bool stencilTest = false;
        uint32_t stencilReadMask = 0xFF;
        uint32_t stencilWriteMask = 0xFF;
        enum class StencilOp { Keep, Zero, Replace, IncrementAndClamp, DecrementAndClamp, Invert, IncrementAndWrap, DecrementAndWrap } stencilFailOp = StencilOp::Keep, stencilPassOp = StencilOp::Keep, stencilDepthFailOp = StencilOp::Keep;
        enum class CompareOp { Never, Less, Equal, LEqual, Greater, NotEqual, GEqual, Always } stencilCompareOp = CompareOp::Always;
        uint32_t stencilReference = 0;
        uint32_t stencilCompareMask = 0xFF;
        uint32_t stencilWriteMask = 0xFF;
        
        bool blendEnable = false;
        enum class BlendFactor { Zero, One, SrcColor, OneMinusSrcColor, DstColor, OneMinusDstColor, SrcAlpha, OneMinusSrcAlpha, DstAlpha, OneMinusDstAlpha, ConstantColor, OneMinusConstantColor, ConstantAlpha, OneMinusConstantAlpha, SrcAlphaSaturate, Src1Color, OneMinusSrc1Color, Src1Alpha, OneMinusSrc1Alpha } srcColorBlendFactor = BlendFactor::SrcAlpha, dstColorBlendFactor = BlendFactor::OneMinusSrcAlpha, srcAlphaBlendFactor = BlendFactor::One, dstAlphaBlendFactor = BlendFactor::Zero;
        enum class BlendOp { Add, Subtract, ReverseSubtract, Min, Max } colorBlendOp = BlendOp::Add, alphaBlendOp = BlendOp::Add;
        float blendConstants[4] = {0, 0, 0, 0};
        uint32_t colorWriteMask = 0xF;
        
        bool logicOpEnable = false;
        enum class LogicOp { Clear, And, AndReverse, Copy, AndInverted, NoOp, Xor, Or, Nor, Equiv, Invert, OrReverse, CopyInverted, OrInverted, Nand, Set } logicOp = LogicOp::Copy;
        
        bool depthClampEnable = false;
        bool rasterizerDiscardEnable = false;
        enum class PolygonMode { Fill, Line, Point, FillRectangleNV } polygonMode = PolygonMode::Fill;
        enum class CullMode { None, Front, Back, FrontAndBack } cullMode = CullMode::Back;
        enum class FrontFace { CounterClockwise, Clockwise } frontFace = FrontFace::CounterClockwise;
        float depthBiasConstant = 0.0f;
        float depthBiasClamp = 0.0f;
        float depthBiasSlopeFactor = 0.0f;
        float lineWidth = 1.0f;
        
        uint32_t sampleCount = 1;
        bool sampleShadingEnable = false;
        float minSampleShading = 0.0f;
        bool alphaToCoverageEnable = false;
        bool alphaToOneEnable = false;
    } renderState;
    
    std::vector<ShaderProperty> properties;
    std::vector<std::string> defines;
    std::string entryPointVS = "main";
    std::string entryPointFS = "main";
    std::string entryPointGS = "main";
    std::string entryPointCS = "main";
};

struct Shader {
    std::string name;
    std::string guid;
    std::string path;
    std::vector<ShaderPass> passes;
    std::vector<std::string> dependencies;
    std::string fallbackShader;
    uint32_t renderQueue = 2000;
    bool isHidden = false;
    bool isBuiltin = false;
    std::string fallbackName = "Hidden/InternalErrorShader";
    uint32_t maximumLOD = 1000;
    bool ignoreProjector = false;
    bool disableBatching = false;
    bool disableInstancing = false;
    bool enableInstancing = true;
    bool enableGPUInstancing = true;
    bool keepAlpha = false;
    bool allowGPUInstancingVariants = true;
    bool enableSRGBWrite = false;
};

struct MaterialProperty {
    enum class Type { Float, Float2, Float3, Float4, Int, Int2, Int3, Int4, Bool, Texture2D, Texture3D, Cubemap, Matrix4x4 } type;
    std::string name;
    std::variant<float, float[2], float[3], float[4], int, int[2], int[3], int[4], bool, uint64_t> value;
    uint32_t textureGUID = 0;
    float min = 0.0f;
    float max = 1.0f;
    bool isHidden = false;
    std::string displayName;
    std::string tooltip;
};

struct Material {
    std::string name;
    std::string guid;
    std::string shaderGUID;
    std::string name;
    uint32_t renderQueue = 2000;
    std::string renderQueueName = "Geometry";
    bool enableInstancing = true;
    bool enableGPUInstancing = true;
    bool doubleSided = false;
    bool alphaToMask = false;
    float alphaCutoff = 0.5f;
    bool receiveShadows = true;
    bool castShadows = true;
    bool receiveGI = true;
    std::unordered_map<std::string, std::variant<float, float[2], float[3], float[4], int, bool, uint64_t>> properties;
    std::unordered_map<std::string, uint64_t> textureProperties;
    std::vector<std::string> shaderKeywords;
    std::vector<std::string> shaderDependencies;
    uint32_t renderQueueOverride = 0;
    bool enableInstancingVariants = true;
    bool enableSRGBWrite = false;
    bool keepAlpha = false;
    bool allowGPUInstancingVariants = true;
    bool enableSRGBWrite = false;
    bool doubleSided = false;
    bool alphaToMask = false;
    float alphaCutoff = 0.5f;
    bool receiveShadows = true;
    bool castShadows = true;
    bool receiveGI = true;
    std::string lightmapTexture;
    float lightmapScaleOffset[4] = {1, 1, 0, 0};
    std::string shaderGUID;
    std::unordered_map<std::string, float> floatProperties;
    std::unordered_map<std::string, float[2]> vector2Properties;
    std::unordered_map<std::string, float[3]> vector3Properties;
    std::unordered_map<std::string, float[4]> vector4Properties;
    std::unordered_map<std::string, int> intProperties;
    std::unordered_map<std::string, bool> boolProperties;
    std::unordered_map<std::string, uint64_t> textureProperties;
    std::unordered_map<std::string, uint64_t> matrixProperties;
    std::vector<std::string> shaderKeywords;
    std::string customRenderPipelineTag;
    bool dirty = true;
    uint32_t renderQueueOverride = 0;
    bool enableInstancing = true;
    bool enableGPUInstancing = true;
    bool doubleSided = false;
    bool alphaToMask = false;
    float alphaCutoff = 0.5f;
    bool receiveShadows = true;
    bool castShadows = true;
    bool receiveGI = true;
    std::string lightmapTexture;
    float lightmapScaleOffset[4] = {1, 1, 0, 0};
};

struct LightData {
    enum class Type : uint8_t { Directional = 0, Point = 1, Spot = 2, Area = 3, Environment = 4 } type = Type::Directional;
    float color[3] = {1, 1, 1};
    float intensity = 1.0f;
    float range = 100.0f;
    float spotAngle = 45.0f;
    float innerAngle = 30.0f;
    float rangeAttenuation = 1.0f;
    float constantAttenuation = 1.0f;
    float linearAttenuation = 0.0f;
    float quadraticAttenuation = 0.0f;
    bool castShadows = true;
    float shadowStrength = 1.0f;
    float shadowBias = 0.005f;
    float shadowNormalBias = 0.0f;
    float shadowNearPlane = 0.1f;
    float shadowFarPlane = 100.0f;
    float shadowResolution = 1024;
    float shadowBias = 0.005f;
    float shadowNormalBias = 0.0f;
    float shadowNearPlane = 0.1f;
    float shadowFarPlane = 100.0f;
    bool useCookie = false;
    uint64_t cookieTexture = 0;
    bool drawHalo = false;
    float haloSize = 0.0f;
    float haloStrength = 1.0f;
    float flareFade = 1.0f;
    bool useColorTemperature = false;
    float colorTemperature = 6500.0f;
    bool useCct = false;
    bool usePhotometric = false;
    float iesProfileIntensity = 1.0f;
    std::string iesProfilePath;
    bool useCookie = false;
    uint64_t cookieTexture = 0;
    bool drawHalo = false;
    float haloSize = 0.0f;
    float haloStrength = 1.0f;
    float flareFade = 1.0f;
};

struct LightProbeData {
    float shCoefficients[27] = {}; // 9 SH coefficients * 3 channels
    float position[3] = {0, 0, 0};
    float boundingBox[6] = {-1,-1,-1, 1,1,1};
    uint32_t probeIndex = 0;
};

struct LightingSettings {
    enum class AmbientMode { Skybox, Gradient, Color, Custom } ambientMode = AmbientMode::Skybox;
    float ambientSkyColor[3] = {0.212f, 0.227f, 0.259f};
    float ambientEquatorColor[3] = {0.114f, 0.125f, 0.133f};
    float ambientGroundColor[3] = {0.0f, 0.0f, 0.0f};
    float ambientIntensity = 1.0f;
    float ambientIntensityMultiplier = 1.0f;
    float ambientIntensity = 1.0f;
    float defaultReflectionIntensity = 1.0f;
    float defaultReflectionResolution = 128;
    int defaultReflectionRefreshMode = 0;
    float defaultReflectionRefreshTime = 1.0f;
    int reflectionCubemapCompression = 1;
    float reflectionBounces = 1.0f;
    float reflectionIntensity = 1.0f;
    bool useRadianceCubemap = true;
    bool useIrradianceCubemap = true;
    uint64_t customReflectionCubemap = 0;
    uint64_t skyboxMaterial = 0;
    bool useSkybox = true;
    float sunSize = 0.04f;
    float sunConvergence = 0.0f;
    float sunIntensity = 1.0f;
    float sunColor[3] = {1, 0.95686f, 0.83921f};
    float sunDirection[3] = {0.5f, -0.5f, 0.5f};
};

struct RenderSettings {
    float fogColor[3] = {0.5f, 0.5f, 0.5f};
    enum class FogMode { Linear, Exponential, ExponentialSquared } fogMode = FogMode::Exponential;
    float fogDensity = 0.01f;
    float fogStart = 0.0f;
    float fogEnd = 1000.0f;
    float ambientIntensity = 1.0f;
    float skyboxIntensity = 1.0f;
    float halosStrength = 1.0f;
    float flareStrength = 1.0f;
    float flareFadeSpeed = 1.0f;
    bool hdr = true;
    int hdrBitDepth = 16;
    bool useHDR = true;
    int colorSpace = 1; // 0 = Gamma, 1 = Linear
    int tier = 2;
    int shaderLodBias = 0;
    int maxLOD = 1000;
    float lodBias = 0.0f;
    float maximumLOD = 1000.0f;
    int anisoLevel = 4;
    int textureQuality = 2;
    int shadowQuality = 2;
    int shadowResolution = 2;
    float shadowDistance = 150.0f;
    int shadowCascades = 4;
    float shadowCascade2Split = 0.033f;
    float shadowCascade4Split[3] = {0.067f, 0.2f, 0.467f};
    float shadowDistance = 150.0f;
    float shadowNearPlane = 0.3f;
    float shadowFarPlane = 100.0f;
    float shadowResolution = 1024.0f;
    float shadowBias = 0.005f;
    float shadowNormalBias = 0.0f;
    int shadowProjection = 0; // 0=Perspective, 1=Orthographic
    int shadowCascades = 4;
    float shadowCascade2Split = 0.033f;
    float shadowCascade4Split[3] = {0.067f, 0.2f, 0.467f};
    float shadowDistance = 150.0f;
    float shadowNearPlane = 0.3f;
    float shadowFarPlane = 100.0f;
    float shadowResolution = 1024.0f;
    float shadowBias = 0.005f;
    float shadowNormalBias = 0.0f;
    int shadowProjection = 0;
    int shadowCascades = 4;
    float shadowCascade2Split = 0.033f;
    float shadowCascade4Split[3] = {0.067f, 0.2f, 0.467f};
    float shadowDistance = 150.0f;
    float shadowNearPlane = 0.3f;
    float shadowFarPlane = 100.0f;
    float shadowResolution = 1024.0f;
    float shadowBias = 0.005f;
    float shadowNormalBias = 0.0f;
    int shadowProjection = 0;
    int shadowCascades = 4;
};

} // namespace kartgib::editor