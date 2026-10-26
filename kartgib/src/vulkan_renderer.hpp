#pragma once

#define VK_USE_PLATFORM_WIN32_KHR
#include <vulkan/vulkan.h>
#include <windows.h>
#include <filesystem>
#include <vector>
#include <string>
#include <stdexcept>
#include <optional>
#include <set>
#include <algorithm>
#include <array>
#include <fstream>
#include <iostream>
#include <cstdint>
#include <limits>

#include "win32_window.hpp"

struct QueueFamilyIndices {
    std::optional<uint32_t> graphicsFamily;
    std::optional<uint32_t> presentFamily;
    
    bool isComplete() const {
        return graphicsFamily.has_value() && presentFamily.has_value();
    }
};

struct SwapChainSupportDetails {
    VkSurfaceCapabilitiesKHR capabilities;
    std::vector<VkSurfaceFormatKHR> formats;
    std::vector<VkPresentModeKHR> presentModes;
};

struct Vertex {
    float pos[3];
    float normal[3];
    float uv[2];
    
    static VkVertexInputBindingDescription getBindingDescription() {
        VkVertexInputBindingDescription binding{};
        binding.binding = 0;
        binding.stride = sizeof(Vertex);
        binding.inputRate = VK_VERTEX_INPUT_RATE_VERTEX;
        return binding;
    }
    
    static std::array<VkVertexInputAttributeDescription, 3> getAttributeDescriptions() {
        std::array<VkVertexInputAttributeDescription, 3> attributes{};
        
        attributes[0].binding = 0;
        attributes[0].location = 0;
        attributes[0].format = VK_FORMAT_R32G32B32_SFLOAT;
        attributes[0].offset = offsetof(Vertex, pos);
        
        attributes[1].binding = 0;
        attributes[1].location = 1;
        attributes[1].format = VK_FORMAT_R32G32B32_SFLOAT;
        attributes[1].offset = offsetof(Vertex, normal);
        
        attributes[2].binding = 0;
        attributes[2].location = 2;
        attributes[2].format = VK_FORMAT_R32G32_SFLOAT;
        attributes[2].offset = offsetof(Vertex, uv);
        
        return attributes;
    }
};

struct UniformBufferObject {
    alignas(16) float view[16];
    alignas(16) float proj[16];
    alignas(16) float model[16];
    alignas(16) float lightDir[4];
    alignas(16) float cameraPos[4];
    alignas(4) float time;
    alignas(4) float padding[3];
    alignas(16) float cascadeVp[4][16];
    alignas(16) float cascadeSplits[4];
};

class VulkanRenderer {
public:
    VulkanRenderer(Win32Window* windowHandle, bool enableValidation = false);
    ~VulkanRenderer();
    
    VulkanRenderer(const VulkanRenderer&) = delete;
    VulkanRenderer& operator=(const VulkanRenderer&) = delete;
    
    void initialize();
    void cleanup();
    void noteRenderPath(const char* scene, int entities, int meshEntities, int voxels,
        int tiles, int foliageGenerated, int waterMesh);
    void recreateSwapchain();
    void cleanupSwapchain();
    void waitIdle() { vkDeviceWaitIdle(device_); }
    
    VkDevice getDevice() const { return device_; }
    VkPhysicalDevice getPhysicalDevice() const { return physicalDevice_; }
    VkQueue getGraphicsQueue() const { return graphicsQueue_; }
    VkQueue getPresentQueue() const { return presentQueue_; }
    VkCommandPool getCommandPool() const { return commandPool_; }
    VkRenderPass getRenderPass() const { return renderPass_; }
    VkExtent2D getSwapchainExtent() const { return swapchainExtent_; }
    uint32_t getSwapchainImageCount() const { return swapchainImages_.size(); }
    VkFormat getSwapchainImageFormat() const { return swapchainImageFormat_; }
    
    // Mesh upload (public for game loop)
    struct MeshBuffer {
        VkBuffer vertexBuffer = VK_NULL_HANDLE;
        VkDeviceMemory vertexBufferMemory = VK_NULL_HANDLE;
        VkBuffer indexBuffer = VK_NULL_HANDLE;
        VkDeviceMemory indexBufferMemory = VK_NULL_HANDLE;
        uint32_t indexCount = 0;
    };
    
    MeshBuffer createMeshBuffer(const std::vector<Vertex>& vertices, const std::vector<uint32_t>& indices);
    void destroyMeshBuffer(MeshBuffer& mesh);
    
    // Buffer operations (public for game loop)
    void createBuffer(VkDeviceSize size, VkBufferUsageFlags usage, VkMemoryPropertyFlags properties,
                      VkBuffer& buffer, VkDeviceMemory& bufferMemory);
    void copyBuffer(VkBuffer srcBuffer, VkBuffer dstBuffer, VkDeviceSize size);
    
    // Uniform buffer
    struct UniformBuffer {
        VkBuffer buffer = VK_NULL_HANDLE;
        VkDeviceMemory memory = VK_NULL_HANDLE;
        void* mapped = nullptr;
    };
    
    UniformBuffer createUniformBuffer(VkDeviceSize size);
    void destroyUniformBuffer(UniformBuffer& ubo);
    void updateUniformBuffer(UniformBuffer& ubo, const void* data, VkDeviceSize size);
    
    // Descriptor sets
    VkDescriptorSetLayout getDescriptorSetLayout() const { return descriptorSetLayout_; }
    VkDescriptorPool getDescriptorPool() const { return descriptorPool_; }
    std::vector<VkDescriptorSet> allocateDescriptorSets(uint32_t count);
    
    // Draw frame with explicit parameters (no GameLoop dependency)
    void drawFrame(VkBuffer vertexBuffer, VkBuffer indexBuffer, uint32_t indexCount,
                   const UniformBufferObject& uboData);
    
    // Debug mode: render a simple clip-space triangle for diagnostics
    void enableDebugTriangleMode(bool enable);
    void drawDebugTriangle();
    void captureFramebuffer(const std::string& filename);
    void createAtmospherePipeline();
    void destroyAtmospherePipeline();
    void drawAtmosphere(float timeSeconds);
    void allocateFrameDescriptors();
    void writeFrameDescriptor(const UniformBuffer& ubo);
    void setG04Sample(bool enable, bool skipAtmosphere, const char* label);
    bool forensicsBusy() const { return forensicsArmed_; }
    bool shadowCertBusy() const { return shadowCertArmed_; }
    bool chunkTourBusy() const { return chunkTourArmed_; }
    float chunkFocusX() const { return chunkFocusX_; }
    void armChunkTour();
    void armOceanTour();
    bool oceanTourBusy() const { return oceanTourArmed_; }
    float oceanSimTime() const { return oceanSimTime_; }
    void armProductTour();
    bool productTourBusy() const { return productTourArmed_; }
    int productStep() const { return productStep_; }
    void uploadInstances(const float* xyz, int count);
    void noteCpuMs(float ms);
    float instGpuMs() const { return instGpuMs_; }
    void requestEditorShot(const char* name);
    bool editorShotBusy() const { return editorShot_; }
    void freezeEditorTime();
    void armShadowCert();
    void armForensics();
    void prepareForensics();
    void configureForensicsPass();
    void retainForensicsFrame(const uint8_t* pixels, bool bgra);
    void publishG05Evidence(const uint8_t* pixels, bool bgra);
    void noteForensicsReadback(uint64_t nonClear, uint64_t uniqueColors, const uint8_t* pixels, bool bgra);
    static void noteValidationMessage();
    int validationCount() const;
    void recordG04Readback(VkCommandBuffer cmd, uint32_t imageIndex);
    void publishG04Readback();
    void createShadowResources();
    void destroyShadowResources();
    void fillCascadeMatrices(UniformBufferObject& ubo);
    void createShadowPipeline();
    void recordShadowPass(VkCommandBuffer cmd, VkBuffer vertexBuffer, VkBuffer indexBuffer,
        uint32_t indexCount, const UniformBufferObject& ubo);
    void prepareShadowCert();
    void prepareChunkTour();
    void noteChunkTour(const uint8_t* pixels, bool bgra);
    void prepareOceanTour();
    void noteOceanTour(const uint8_t* pixels, bool bgra);
    void createProductPipeline();
    void createProductMeshes();
    void drawProduct(VkCommandBuffer cmd);
    void destroyProductPipeline();
    void collectProductTime();
    void prepareProductTour();
    void prepareEditorShot();
    void noteEditorShot(const uint8_t* pixels, bool bgra);
    void noteProductTour(const uint8_t* pixels, bool bgra);
    void noteShadowCert(const uint8_t* pixels, bool bgra);
    void collectGpuTime();
    
private:
    Win32Window* windowHandle_;
    bool enableValidation_;
    
    VkInstance instance_ = VK_NULL_HANDLE;
    VkDebugUtilsMessengerEXT debugMessenger_ = VK_NULL_HANDLE;
    VkSurfaceKHR surface_ = VK_NULL_HANDLE;
    VkPhysicalDevice physicalDevice_ = VK_NULL_HANDLE;
    VkDevice device_ = VK_NULL_HANDLE;
    VkQueue graphicsQueue_ = VK_NULL_HANDLE;
    VkQueue presentQueue_ = VK_NULL_HANDLE;
    VkCommandPool commandPool_ = VK_NULL_HANDLE;
    
    VkSwapchainKHR swapchain_ = VK_NULL_HANDLE;
    std::vector<VkImage> swapchainImages_;
    VkFormat swapchainImageFormat_;
    VkExtent2D swapchainExtent_;
    std::vector<VkImageView> swapchainImageViews_;
    std::vector<VkFramebuffer> swapchainFramebuffers_;
    
    // Depth resources
    std::vector<VkImage> depthImages_;
    std::vector<VkDeviceMemory> depthImageMemories_;
    std::vector<VkImageView> depthImageViews_;
    VkFormat depthFormat_ = VK_FORMAT_D32_SFLOAT;
    
    bool framebufferResized_ = false;
    VkRenderPass renderPass_ = VK_NULL_HANDLE;
    VkPipelineLayout pipelineLayout_ = VK_NULL_HANDLE;
    VkPipeline graphicsPipeline_ = VK_NULL_HANDLE;
    
    VkDescriptorSetLayout descriptorSetLayout_ = VK_NULL_HANDLE;
    VkDescriptorPool descriptorPool_ = VK_NULL_HANDLE;
    std::vector<VkDescriptorSet> descriptorSets_;
    
    std::vector<VkCommandBuffer> commandBuffers_;
    std::vector<VkSemaphore> imageAvailableSemaphores_;
    std::vector<VkSemaphore> renderFinishedSemaphores_;
    std::vector<VkFence> inFlightFences_;
    uint32_t currentFrame_ = 0;
    const uint32_t MAX_FRAMES_IN_FLIGHT = 2;
    
    // Validation layers
    const std::vector<const char*> validationLayers_ = {
        "VK_LAYER_KHRONOS_validation"
    };
    
    // Device extensions
    const std::vector<const char*> deviceExtensions_ = {
        VK_KHR_SWAPCHAIN_EXTENSION_NAME
    };
    
    // Initialization steps
    void createInstance();
    void setupDebugMessenger();
    void createSurface();
    void pickPhysicalDevice();
    void createLogicalDevice();
    void createDescriptorPool();
    void createSwapchain();
    void createDepthResources();
    void createImageViews();
    void createRenderPass();
    void createDescriptorSetLayout();
    void createGraphicsPipeline();
    void createCommandPool();
    void createFramebuffers();
    void createSyncObjects();
    void allocateCommandBuffers();
    
    // Helpers
    bool checkValidationLayerSupport();
    std::vector<const char*> getRequiredExtensions();
    static VKAPI_ATTR VkBool32 VKAPI_CALL debugCallback(
        VkDebugUtilsMessageSeverityFlagBitsEXT messageSeverity,
        VkDebugUtilsMessageTypeFlagsEXT messageType,
        const VkDebugUtilsMessengerCallbackDataEXT* pCallbackData,
        void* pUserData);
    
    QueueFamilyIndices findQueueFamilies(VkPhysicalDevice device);
    bool checkDeviceExtensionSupport(VkPhysicalDevice device);
    SwapChainSupportDetails querySwapchainSupport(VkPhysicalDevice device);
    VkSurfaceFormatKHR chooseSwapSurfaceFormat(const std::vector<VkSurfaceFormatKHR>& availableFormats);
    VkPresentModeKHR chooseSwapPresentMode(const std::vector<VkPresentModeKHR>& availablePresentModes);
    VkExtent2D chooseSwapExtent(const VkSurfaceCapabilitiesKHR& capabilities);
    VkShaderModule createShaderModule(const std::vector<char>& code);
    
    uint32_t findMemoryType(uint32_t typeFilter, VkMemoryPropertyFlags properties);
    void transitionImageLayout(VkImage image, VkFormat format, VkImageLayout oldLayout, VkImageLayout newLayout);
    void copyBufferToImage(VkBuffer buffer, VkImage image, uint32_t width, uint32_t height);
    
    // Debug triangle resources
    bool debugTriangleMode_ = false;
    bool g04Sample_ = false;
    bool g04SkipAtmosphere_ = false;
    bool g04SkipGeometry_ = false;
    bool readbackThisFrame_ = false;
    bool forensicsArmed_ = false;
    float lightDiag_ = 0.0f;
    bool shadowsWanted_ = true;
    bool shadowCertArmed_ = false;
    bool chunkTourArmed_ = false;
    int chunkTourStep_ = -1;
    int chunkTourWarmup_ = 0;
    bool oceanTourArmed_ = false;
    int oceanTourStep_ = -1;
    int oceanTourWarmup_ = 0;
    float oceanSimTime_ = 0.0f;
    bool productTourArmed_ = false;
    bool editorShot_ = false;
    bool editorFreeze_ = false;
    char editorShotName_[16] = {};
    int productStep_ = -1;
    int productWarmup_ = 0;
    float instGpuMs_ = -1.0f;
    float cpuMinMs_ = 0.0f;
    float cpuMaxMs_ = 0.0f;
    float cpuSumMs_ = 0.0f;
    int cpuCount_ = 0;
    uint32_t instCount_ = 0;
    VkPipeline productPipeline_ = VK_NULL_HANDLE;
    VkQueryPool productQuery_ = VK_NULL_HANDLE;
    VkBuffer grassVb_ = VK_NULL_HANDLE;
    VkBuffer grassIb_ = VK_NULL_HANDLE;
    VkBuffer hudVb_ = VK_NULL_HANDLE;
    VkBuffer hudIb_ = VK_NULL_HANDLE;
    VkBuffer instVb_ = VK_NULL_HANDLE;
    VkDeviceMemory grassMem_ = VK_NULL_HANDLE;
    VkDeviceMemory grassIndexMem_ = VK_NULL_HANDLE;
    VkDeviceMemory hudMem_ = VK_NULL_HANDLE;
    VkDeviceMemory hudIndexMem_ = VK_NULL_HANDLE;
    VkDeviceMemory instMem_ = VK_NULL_HANDLE;
    float chunkFocusX_ = 400.0f;
    int shadowCertStep_ = -1;
    int shadowCertWarmup_ = 0;
    float lastGpuMs_ = 0.0f;
    float timestampPeriod_ = 1.0f;
    uint64_t shadowDarkPixels_ = 0;
    uint64_t shadowPartialPixels_ = 0;
    uint64_t cascadePixels_[4] = {};
    VkImage shadowImage_ = VK_NULL_HANDLE;
    VkDeviceMemory shadowMemory_ = VK_NULL_HANDLE;
    VkImageView shadowView_ = VK_NULL_HANDLE;
    VkSampler shadowSampler_ = VK_NULL_HANDLE;
    VkRenderPass shadowPass_ = VK_NULL_HANDLE;
    VkFramebuffer shadowFramebuffer_ = VK_NULL_HANDLE;
    VkPipeline shadowPipeline_ = VK_NULL_HANDLE;
    VkPipelineLayout shadowLayout_ = VK_NULL_HANDLE;
    VkShaderModule shadowVertModule_ = VK_NULL_HANDLE;
    VkShaderModule shadowFragModule_ = VK_NULL_HANDLE;
    VkQueryPool timeQuery_ = VK_NULL_HANDLE;
    uint64_t skyInFinal_ = 0;
    uint64_t terrainInFinal_ = 0;
    uint64_t diffusePixels_ = 0;
    uint64_t specPixels_ = 0;
    bool geometryOutsideFrustum_ = false;
    bool uniformBindingInvalid_ = false;
    int forensicsStep_ = -1;
    int forensicsWarmup_ = 0;
    uint32_t presentSuccess_ = 0;
    uint32_t presentFail_ = 0;
    uint32_t atmosphereSubmits_ = 0;
    uint32_t terrainSubmits_ = 0;
    uint32_t shadowSubmits_ = 0;
    uint32_t foliageDraws_ = 0;
    uint32_t pipelineFailures_ = 0;
    uint32_t lastIndexCount_ = 0;
    uint64_t skyNonClear_ = 0;
    uint64_t terrainNonClear_ = 0;
    uint64_t combinedNonClear_ = 0;
    uint64_t skyUnique_ = 0;
    uint64_t terrainUnique_ = 0;
    uint64_t combinedUnique_ = 0;
    char deviceName_[128] = {};
    bool swapchainTransferSrc_ = false;
    uint32_t g04SampleFrame_ = 0;
    uint32_t g04Width_ = 0;
    uint32_t g04Height_ = 0;
    const char* g04Label_ = "frame";
    VkBuffer g04Buffer_ = VK_NULL_HANDLE;
    VkDeviceMemory g04Memory_ = VK_NULL_HANDLE;
    VkPipelineLayout debugPipelineLayout_ = VK_NULL_HANDLE;
    VkPipeline debugPipeline_ = VK_NULL_HANDLE;
    VkShaderModule debugVertShaderModule_ = VK_NULL_HANDLE;
    VkShaderModule debugFragShaderModule_ = VK_NULL_HANDLE;
    VkBuffer debugVertexBuffer_ = VK_NULL_HANDLE;
    VkDeviceMemory debugVertexBufferMemory_ = VK_NULL_HANDLE;
    
    VkPipelineLayout atmospherePipelineLayout_ = VK_NULL_HANDLE;
    VkPipeline atmospherePipeline_ = VK_NULL_HANDLE;
    VkShaderModule atmosphereVertShaderModule_ = VK_NULL_HANDLE;
    VkShaderModule atmosphereFragShaderModule_ = VK_NULL_HANDLE;

    void createDebugTrianglePipeline();
    void destroyDebugTrianglePipeline();
    void createDebugTriangleVertexBuffer();
    void destroyDebugTriangleVertexBuffer();
};