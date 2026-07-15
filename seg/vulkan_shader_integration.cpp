// ============================================================================
// Vulkan Shader Integration Implementation
// ============================================================================

#include "vulkan_shader_integration.hpp"
#include <fstream>
#include <iostream>
#include <chrono>

namespace transformer {

// ============================================================================
// SPIRV Loader
// ============================================================================
std::vector<uint32_t> SPIRVLoader::LoadFile(const std::string& path) {
    std::ifstream file(path, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        std::cerr << "[SPIRV] Failed to open: " << path << std::endl;
        return {};
    }
    
    size_t size = file.tellg();
    file.seekg(0, std::ios::beg);
    
    if (size % sizeof(uint32_t) != 0) {
        std::cerr << "[SPIRV] Invalid SPIR-V file size: " << size << std::endl;
        return {};
    }
    
    std::vector<uint32_t> code(size / sizeof(uint32_t));
    file.read(reinterpret_cast<char*>(code.data()), size);
    
    return code;
}

bool SPIRVLoader::Validate(const std::vector<uint32_t>& code) {
    if (code.size() < 5) return false;
    
    // SPIR-V magic number: 0x07230203
    if (code[0] != 0x07230203) {
        std::cerr << "[SPIRV] Invalid magic number: 0x" << std::hex << code[0] << std::dec << std::endl;
        return false;
    }
    
    return true;
}

// ============================================================================
// Vulkan Shader Pipeline
// ============================================================================
VulkanShaderPipeline::VulkanShaderPipeline(VkDevice device, VkPipelineLayout layout)
    : device_(device), layout_(layout) {}

VulkanShaderPipeline::~VulkanShaderPipeline() {
    if (pipeline_ != VK_NULL_HANDLE) {
        vkDestroyPipeline(device_, pipeline_, nullptr);
    }
    if (module_ != VK_NULL_HANDLE) {
        vkDestroyShaderModule(device_, module_, nullptr);
    }
    if (cache_ != VK_NULL_HANDLE) {
        vkDestroyPipelineCache(device_, cache_, nullptr);
    }
}

bool VulkanShaderPipeline::Initialize(const std::vector<uint32_t>& spirv_code,
                                       const ShaderPipelineConfig& config,
                                       VkShaderStageFlagBits stage) {
    if (!SPIRVLoader::Validate(spirv_code)) {
        return false;
    }
    
    // Create shader module
    module_ = CreateShaderModule(spirv_code);
    if (module_ == VK_NULL_HANDLE) {
        return false;
    }
    
    // Create pipeline cache
    VkPipelineCacheCreateInfo cache_info = {};
    cache_info.sType = VK_STRUCTURE_TYPE_PIPELINE_CACHE_CREATE_INFO;
    vkCreatePipelineCache(device_, &cache_info, nullptr, &cache_);
    
    // Shader stage info
    VkPipelineShaderStageCreateInfo stage_info = {};
    stage_info.sType = VK_STRUCTURE_TYPE_PIPELINE_SHADER_STAGE_CREATE_INFO;
    stage_info.stage = stage;
    stage_info.module = module_;
    stage_info.pName = "main";
    
    // Compute pipeline create info
    VkComputePipelineCreateInfo pipeline_info = {};
    pipeline_info.sType = VK_STRUCTURE_TYPE_COMPUTE_PIPELINE_CREATE_INFO;
    pipeline_info.stage = stage_info;
    pipeline_info.layout = layout_;
    
    VkResult result = vkCreateComputePipelines(device_, cache_, 1, &pipeline_info, nullptr, &pipeline_);
    if (result != VK_SUCCESS) {
        std::cerr << "[Vulkan] Failed to create compute pipeline: " << result << std::endl;
        return false;
    }
    
    return true;
}

void VulkanShaderPipeline::Bind(VkCommandBuffer cmd_buffer) {
    vkCmdBindPipeline(cmd_buffer, VK_PIPELINE_BIND_POINT_COMPUTE, pipeline_);
}

void VulkanShaderPipeline::Dispatch(VkCommandBuffer cmd_buffer, uint32_t x, uint32_t y, uint32_t z) {
    vkCmdDispatch(cmd_buffer, x, y, z);
}

VkShaderModule VulkanShaderPipeline::CreateShaderModule(const std::vector<uint32_t>& code) {
    VkShaderModuleCreateInfo create_info = {};
    create_info.sType = VK_STRUCTURE_TYPE_SHADER_MODULE_CREATE_INFO;
    create_info.codeSize = code.size() * sizeof(uint32_t);
    create_info.pCode = code.data();
    
    VkShaderModule module = VK_NULL_HANDLE;
    VkResult result = vkCreateShaderModule(device_, &create_info, nullptr, &module);
    if (result != VK_SUCCESS) {
        std::cerr << "[Vulkan] Failed to create shader module: " << result << std::endl;
        return VK_NULL_HANDLE;
    }
    
    return module;
}

// ============================================================================
// RDNA3 Shader Manager
// ============================================================================
RDNA3ShaderManager::RDNA3ShaderManager() = default;
RDNA3ShaderManager::~RDNA3ShaderManager() {
    Cleanup();
}

bool RDNA3ShaderManager::Initialize(VkDevice device, VkPipelineLayout layout) {
    device_ = device;
    layout_ = layout;
    
    // Configure for RDNA3
    config_.use_wave64 = true;
    config_.lds_size = 65536;  // 64KB LDS
    
    return true;
}

void RDNA3ShaderManager::Cleanup() {
    rmsnorm_pipeline_.reset();
    matmul_pipeline_.reset();
    softmax_pipeline_.reset();
    flash_attn_pipeline_.reset();
    q4k_gemm_pipeline_.reset();
}

bool RDNA3ShaderManager::LoadRawrXDShaders(const std::string& shader_dir) {
    std::cout << "[RDNA3] Loading RawrXD shaders from: " << shader_dir << std::endl;
    
    // Load RMSNorm shader
    if (!LoadPipeline(rmsnorm_pipeline_, shader_dir + "/rms_norm_fp16.spv", VK_SHADER_STAGE_COMPUTE_BIT)) {
        std::cerr << "[RDNA3] Failed to load RMSNorm shader" << std::endl;
    }
    
    // Load MatMul shader
    if (!LoadPipeline(matmul_pipeline_, shader_dir + "/matmul_fp16.spv", VK_SHADER_STAGE_COMPUTE_BIT)) {
        std::cerr << "[RDNA3] Failed to load MatMul shader" << std::endl;
    }
    
    // Load Softmax shader
    if (!LoadPipeline(softmax_pipeline_, shader_dir + "/softmax_fp16.spv", VK_SHADER_STAGE_COMPUTE_BIT)) {
        std::cerr << "[RDNA3] Failed to load Softmax shader" << std::endl;
    }
    
    // Load Flash Attention shader
    if (!LoadPipeline(flash_attn_pipeline_, shader_dir + "/flash_attention_fp8_tiled.spv", VK_SHADER_STAGE_COMPUTE_BIT)) {
        std::cerr << "[RDNA3] Failed to load Flash Attention shader" << std::endl;
    }
    
    // Load Q4K GEMM shader
    if (!LoadPipeline(q4k_gemm_pipeline_, shader_dir + "/fused_q4k_tile_gemm.spv", VK_SHADER_STAGE_COMPUTE_BIT)) {
        std::cerr << "[RDNA3] Failed to load Q4K GEMM shader" << std::endl;
    }
    
    std::cout << "[RDNA3] Shader loading complete" << std::endl;
    return IsComplete();
}

bool RDNA3ShaderManager::LoadPipeline(std::unique_ptr<VulkanShaderPipeline>& pipeline,
                                      const std::string& path,
                                      VkShaderStageFlagBits stage) {
    auto code = SPIRVLoader::LoadFile(path);
    if (code.empty()) {
        return false;
    }
    
    pipeline = std::make_unique<VulkanShaderPipeline>(device_, layout_);
    if (!pipeline->Initialize(code, config_, stage)) {
        pipeline.reset();
        return false;
    }
    
    std::cout << "[RDNA3] Loaded: " << path << std::endl;
    return true;
}

bool RDNA3ShaderManager::IsComplete() const {
    return rmsnorm_pipeline_ && matmul_pipeline_ && softmax_pipeline_ && 
           flash_attn_pipeline_ && q4k_gemm_pipeline_;
}

std::string RDNA3ShaderManager::GetStatus() const {
    std::string status = "RDNA3 Shader Status:\n";
    status += "  RMSNorm: " + std::string(rmsnorm_pipeline_ ? "✓" : "✗") + "\n";
    status += "  MatMul: " + std::string(matmul_pipeline_ ? "✓" : "✗") + "\n";
    status += "  Softmax: " + std::string(softmax_pipeline_ ? "✓" : "✗") + "\n";
    status += "  Flash Attention: " + std::string(flash_attn_pipeline_ ? "✓" : "✗") + "\n";
    status += "  Q4K GEMM: " + std::string(q4k_gemm_pipeline_ ? "✓" : "✗") + "\n";
    return status;
}

// ============================================================================
// GPU Transformer Dispatcher
// ============================================================================
GPUTransformerDispatcher::GPUTransformerDispatcher() = default;
GPUTransformerDispatcher::~GPUTransformerDispatcher() {
    // Cleanup descriptor layouts
    if (rmsnorm_layout_ != VK_NULL_HANDLE) {
        vkDestroyDescriptorSetLayout(device_, rmsnorm_layout_, nullptr);
    }
    if (matmul_layout_ != VK_NULL_HANDLE) {
        vkDestroyDescriptorSetLayout(device_, matmul_layout_, nullptr);
    }
    if (flash_attn_layout_ != VK_NULL_HANDLE) {
        vkDestroyDescriptorSetLayout(device_, flash_attn_layout_, nullptr);
    }
}

bool GPUTransformerDispatcher::Initialize(VkDevice device, VkQueue queue, uint32_t queue_family,
                                          VkCommandPool pool, VkDescriptorPool descriptor_pool) {
    device_ = device;
    queue_ = queue;
    queue_family_ = queue_family;
    pool_ = pool;
    descriptor_pool_ = descriptor_pool;
    
    CreateDescriptorLayouts();
    
    return true;
}

void GPUTransformerDispatcher::CreateDescriptorLayouts() {
    // RMSNorm layout: input, output, weights
    VkDescriptorSetLayoutBinding bindings[3] = {};
    for (int i = 0; i < 3; i++) {
        bindings[i].binding = i;
        bindings[i].descriptorType = VK_DESCRIPTOR_TYPE_STORAGE_BUFFER;
        bindings[i].descriptorCount = 1;
        bindings[i].stageFlags = VK_SHADER_STAGE_COMPUTE_BIT;
    }
    
    VkDescriptorSetLayoutCreateInfo layout_info = {};
    layout_info.sType = VK_STRUCTURE_TYPE_DESCRIPTOR_SET_LAYOUT_CREATE_INFO;
    layout_info.bindingCount = 3;
    layout_info.pBindings = bindings;
    vkCreateDescriptorSetLayout(device_, &layout_info, nullptr, &rmsnorm_layout_);
    
    // MatMul layout: A, B, C
    vkCreateDescriptorSetLayout(device_, &layout_info, nullptr, &matmul_layout_);
    
    // Flash Attention layout: Q, K, V, output
    VkDescriptorSetLayoutBinding attn_bindings[4] = {};
    for (int i = 0; i < 4; i++) {
        attn_bindings[i].binding = i;
        attn_bindings[i].descriptorType = VK_DESCRIPTOR_TYPE_STORAGE_BUFFER;
        attn_bindings[i].descriptorCount = 1;
        attn_bindings[i].stageFlags = VK_SHADER_STAGE_COMPUTE_BIT;
    }
    
    VkDescriptorSetLayoutCreateInfo attn_layout_info = {};
    attn_layout_info.sType = VK_STRUCTURE_TYPE_DESCRIPTOR_SET_LAYOUT_CREATE_INFO;
    attn_layout_info.bindingCount = 4;
    attn_layout_info.pBindings = attn_bindings;
    vkCreateDescriptorSetLayout(device_, &attn_layout_info, nullptr, &flash_attn_layout_);
}

void GPUTransformerDispatcher::RMSNorm(VkBuffer input, VkBuffer output, VkBuffer weights,
                                     uint32_t size, float epsilon, VkCommandBuffer cmd) {
    if (!shader_manager_ || shader_manager_->GetRMSNormPipeline() == VK_NULL_HANDLE) {
        return;
    }
    
    // Bind pipeline
    vkCmdBindPipeline(cmd, VK_PIPELINE_BIND_POINT_COMPUTE, shader_manager_->GetRMSNormPipeline());
    
    // TODO: Bind descriptor sets with buffers
    // TODO: Push constants for size, epsilon
    
    // Dispatch: one workgroup per 256 elements
    uint32_t groups = (size + 255) / 256;
    vkCmdDispatch(cmd, groups, 1, 1);
}

void GPUTransformerDispatcher::MatMul(VkBuffer a, VkBuffer b, VkBuffer c,
                                       uint32_t m, uint32_t k, uint32_t n,
                                       VkCommandBuffer cmd) {
    if (!shader_manager_ || shader_manager_->GetMatMulPipeline() == VK_NULL_HANDLE) {
        return;
    }
    
    vkCmdBindPipeline(cmd, VK_PIPELINE_BIND_POINT_COMPUTE, shader_manager_->GetMatMulPipeline());
    
    // Dispatch: 16x16 tiles
    uint32_t groups_x = (m + 15) / 16;
    uint32_t groups_y = (n + 15) / 16;
    vkCmdDispatch(cmd, groups_x, groups_y, 1);
}

void GPUTransformerDispatcher::FlashAttention(VkBuffer q, VkBuffer k, VkBuffer v, VkBuffer output,
                                               uint32_t seq_len, uint32_t num_heads, uint32_t head_dim,
                                               VkCommandBuffer cmd) {
    if (!shader_manager_ || shader_manager_->GetFlashAttentionPipeline() == VK_NULL_HANDLE) {
        return;
    }
    
    vkCmdBindPipeline(cmd, VK_PIPELINE_BIND_POINT_COMPUTE, shader_manager_->GetFlashAttentionPipeline());
    
    // Dispatch: one workgroup per head
    vkCmdDispatch(cmd, num_heads, 1, 1);
}

void GPUTransformerDispatcher::Q4KGEMM(VkBuffer a, VkBuffer b, VkBuffer c,
                                        uint32_t m, uint32_t n, uint32_t k,
                                        VkCommandBuffer cmd) {
    if (!shader_manager_ || shader_manager_->GetQ4KGEMMPipeline() == VK_NULL_HANDLE) {
        return;
    }
    
    vkCmdBindPipeline(cmd, VK_PIPELINE_BIND_POINT_COMPUTE, shader_manager_->GetQ4KGEMMPipeline());
    
    // Dispatch for Q4K quantized GEMM
    uint32_t groups_x = (m + 15) / 16;
    uint32_t groups_y = (n + 15) / 16;
    vkCmdDispatch(cmd, groups_x, groups_y, 1);
}

// ============================================================================
// Performance Metrics
// ============================================================================
void GPUPerformanceMetrics::Print() const {
    std::cout << "========================================" << std::endl;
    std::cout << "GPU Performance Metrics" << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << "RMSNorm: " << rmsnorm_time_ms << " ms" << std::endl;
    std::cout << "MatMul: " << matmul_time_ms << " ms" << std::endl;
    std::cout << "Flash Attention: " << flash_attn_time_ms << " ms" << std::endl;
    std::cout << "Total Layer: " << total_layer_time_ms << " ms" << std::endl;
    std::cout << "Throughput: " << tokens_per_sec << " tok/s" << std::endl;
    std::cout << "GPU Utilization: " << gpu_utilization << "%" << std::endl;
    std::cout << "Memory Bandwidth: " << memory_bandwidth_gbps << " GB/s" << std::endl;
    std::cout << "========================================" << std::endl;
}

} // namespace transformer
