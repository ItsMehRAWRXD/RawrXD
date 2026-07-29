//============================================================================
// nevm_core.cpp
// RawrXD Neural Execution Virtual Machine - Implementation
//============================================================================

#include "nevm_core.hpp"
#include <algorithm>
#include <string>
#include <chrono>

namespace RawrXD {
namespace NEVM {

//============================================================================
// External ASM Functions
//============================================================================
extern "C" {
    void NanoMatMul_LUT2_Kernel(const uint8_t* indices, const float* activations, 
                                   float* output, const float* codebook, uint64_t count);
    void NanoMatMul_XNOR_Kernel(const uint8_t* weights, const float* activations,
                                 float* output, uint64_t count);
    void Q4_Dequantize_Kernel(const uint8_t* input, float* output, uint64_t count,
                               float scale, float zero_point);
    void Q8_Dequantize_Kernel(const uint8_t* input, float* output, uint64_t count,
                               float scale);
}

//============================================================================
// NeuralExecutionVM Implementation
//============================================================================

NeuralExecutionVM::NeuralExecutionVM(size_t ram_budget, size_t vram_budget)
    : file_handle_(INVALID_HANDLE_VALUE)
    , file_mapping_(nullptr)
    , mapped_base_(nullptr)
    , mapped_size_(0)
    , model_loaded_(false)
    , ram_budget_(ram_budget)
    , vram_budget_(vram_budget) {
    
    // Initialize components
    tensor_viz_ = std::make_unique<TensorVirtualizer>();
    residency_mgr_ = std::make_unique<ResidencyManager>(ram_budget, vram_budget);
    codec_engine_ = std::make_unique<CodecEngine>();
    kernel_dispatch_ = std::make_unique<KernelDispatcher>();
    
    // Initialize stats
    stats_ = {};
}

NeuralExecutionVM::~NeuralExecutionVM() {
    UnloadModel();
}

bool NeuralExecutionVM::LoadModel(const std::wstring& model_path) {
    if (model_loaded_) {
        UnloadModel();
    }
    
    // Map the file
    if (!MapFile(model_path)) {
        last_error_ = "Failed to map model file";
        return false;
    }
    
    // Parse header
    if (!ParseHeader()) {
        UnmapFile();
        last_error_ = "Invalid model header";
        return false;
    }
    
    // Build tensor registry
    if (!BuildTensorRegistry()) {
        UnmapFile();
        last_error_ = "Failed to build tensor registry";
        return false;
    }
    
    model_loaded_ = true;
    return true;
}

bool NeuralExecutionVM::MapFile(const std::wstring& path) {
    file_handle_ = CreateFileW(
        path.c_str(),
        GENERIC_READ,
        FILE_SHARE_READ,
        nullptr,
        OPEN_EXISTING,
        FILE_FLAG_SEQUENTIAL_SCAN,
        nullptr
    );
    
    if (file_handle_ == INVALID_HANDLE_VALUE) {
        return false;
    }
    
    LARGE_INTEGER file_size;
    if (!GetFileSizeEx(file_handle_, &file_size)) {
        CloseHandle(file_handle_);
        file_handle_ = INVALID_HANDLE_VALUE;
        return false;
    }
    
    mapped_size_ = static_cast<size_t>(file_size.QuadPart);
    
    file_mapping_ = CreateFileMapping(
        file_handle_,
        nullptr,
        PAGE_READONLY,
        0, 0,
        nullptr
    );
    
    if (!file_mapping_) {
        CloseHandle(file_handle_);
        file_handle_ = INVALID_HANDLE_VALUE;
        return false;
    }
    
    mapped_base_ = MapViewOfFile(
        file_mapping_,
        FILE_MAP_READ,
        0, 0, 0
    );
    
    if (!mapped_base_) {
        CloseHandle(file_mapping_);
        CloseHandle(file_handle_);
        file_handle_ = INVALID_HANDLE_VALUE;
        return false;
    }
    
    return true;
}

void NeuralExecutionVM::UnmapFile() {
    if (mapped_base_) {
        UnmapViewOfFile(mapped_base_);
        mapped_base_ = nullptr;
    }
    
    if (file_mapping_) {
        CloseHandle(file_mapping_);
        file_mapping_ = nullptr;
    }
    
    if (file_handle_ != INVALID_HANDLE_VALUE) {
        CloseHandle(file_handle_);
        file_handle_ = INVALID_HANDLE_VALUE;
    }
    
    mapped_size_ = 0;
}

bool NeuralExecutionVM::ParseHeader() {
    if (mapped_size_ < sizeof(ModelROMHeader)) {
        return false;
    }
    
    const ModelROMHeader* header = static_cast<const ModelROMHeader*>(mapped_base_);
    
    if (!header->Validate()) {
        return false;
    }
    
    if (header->total_file_size > mapped_size_) {
        return false;
    }
    
    return true;
}

bool NeuralExecutionVM::BuildTensorRegistry() {
    const ModelROMHeader* header = static_cast<const ModelROMHeader*>(mapped_base_);
    
    // Tensor directory starts at header->tensor_dir_offset
    const uint8_t* dir_ptr = static_cast<const uint8_t*>(mapped_base_) + header->tensor_dir_offset;
    
    for (uint32_t i = 0; i < header->tensor_count; ++i) {
        // Read tensor descriptor from directory
        // Format: [name_len:4][name][desc_size:4][descriptor_data]
        uint32_t name_len = *reinterpret_cast<const uint32_t*>(dir_ptr);
        dir_ptr += 4;
        
        std::string name(reinterpret_cast<const char*>(dir_ptr), name_len);
        dir_ptr += name_len;
        
        uint32_t desc_size = *reinterpret_cast<const uint32_t*>(dir_ptr);
        dir_ptr += 4;
        
        // Parse descriptor
        TensorStreamDesc desc;
        desc.name = name;
        
        // Copy descriptor data
        std::memcpy(&desc.file_offset, dir_ptr, sizeof(uint64_t));
        dir_ptr += sizeof(uint64_t);
        std::memcpy(&desc.compressed_size, dir_ptr, sizeof(uint64_t));
        dir_ptr += sizeof(uint64_t);
        std::memcpy(&desc.uncompressed_size, dir_ptr, sizeof(uint64_t));
        dir_ptr += sizeof(uint64_t);
        desc.storage_format = static_cast<TensorFormat>(*dir_ptr++);
        desc.preferred_format = static_cast<TensorFormat>(*dir_ptr++);
        std::memcpy(&desc.block_size, dir_ptr, sizeof(uint32_t));
        dir_ptr += sizeof(uint32_t);
        std::memcpy(&desc.importance_score, dir_ptr, sizeof(float));
        dir_ptr += sizeof(float);
        desc.is_sparse = (*dir_ptr++) != 0;
        std::memcpy(&desc.sparse_mask_offset, dir_ptr, sizeof(uint64_t));
        dir_ptr += sizeof(uint64_t);
        
        tensor_registry_[name] = desc;
    }
    
    return true;
}

void NeuralExecutionVM::UnloadModel() {
    // Clear cache
    {
        std::lock_guard<std::mutex> lock(cache_mutex_);
        tensor_cache_.clear();
    }
    
    tensor_registry_.clear();
    UnmapFile();
    model_loaded_ = false;
}

ExecutionView* NeuralExecutionVM::AcquireTensor(const std::string& tensor_name) {
    if (!model_loaded_) {
        last_error_ = "No model loaded";
        return nullptr;
    }
    
    // Check cache first
    {
        std::lock_guard<std::mutex> lock(cache_mutex_);
        auto it = tensor_cache_.find(tensor_name);
        if (it != tensor_cache_.end()) {
            it->second->ref_count++;
            it->second->last_access_tick = GetTickCount64();
            
            // Update stats
            std::lock_guard<std::mutex> stats_lock(stats_mutex_);
            stats_.cache_hits++;
            
            return it->second.get();
        }
    }
    
    // Find descriptor
    auto reg_it = tensor_registry_.find(tensor_name);
    if (reg_it == tensor_registry_.end()) {
        last_error_ = "Tensor not found: " + tensor_name;
        return nullptr;
    }
    
    // Decode tensor
    ExecutionView* view = DecodeTensor(reg_it->second);
    if (!view) {
        return nullptr;
    }
    
    // Add to cache
    {
        std::lock_guard<std::mutex> lock(cache_mutex_);
        tensor_cache_[tensor_name] = std::unique_ptr<ExecutionView>(view);
    }
    
    // Update stats
    {
        std::lock_guard<std::mutex> stats_lock(stats_mutex_);
        stats_.cache_misses++;
        stats_.tensors_loaded++;
        stats_.bytes_in_ram += view->byte_size;
    }
    
    return view;
}

ExecutionView* NeuralExecutionVM::DecodeTensor(const TensorStreamDesc& desc) {
    auto start_time = std::chrono::high_resolution_clock::now();
    
    ExecutionView* view = new ExecutionView();
    view->format = desc.preferred_format;
    view->element_count = desc.uncompressed_size / sizeof(float);
    view->byte_size = desc.uncompressed_size;
    view->residency = ResidencyState::RAM_RESIDENT;
    view->ref_count = 1;
    view->last_access_tick = GetTickCount64();
    
    // Allocate aligned memory
    view->data = _aligned_malloc(view->byte_size, NEVM_CACHE_LINE);
    if (!view->data) {
        delete view;
        last_error_ = "Failed to allocate tensor memory";
        return nullptr;
    }
    
    // Get source data pointer
    const uint8_t* src = static_cast<const uint8_t*>(mapped_base_) + desc.file_offset;
    
    // Decode based on format
    bool decode_success = false;
    
    switch (desc.storage_format) {
        case TensorFormat::FP32:
            std::memcpy(view->data, src, desc.compressed_size);
            decode_success = true;
            break;
            
        case TensorFormat::FP16:
            // FP16 to FP32 conversion
            codec_engine_->ConvertFP16ToFP32(
                reinterpret_cast<const uint16_t*>(src),
                reinterpret_cast<float*>(view->data),
                view->element_count
            );
            decode_success = true;
            break;
            
        case TensorFormat::Q4_0:
        case TensorFormat::Q4_K:
            // Q4 dequantization
            {
                float scale = *reinterpret_cast<const float*>(src);
                float zero = 0.0f;  // Q4_0 uses implied zero
                Q4_Dequantize_Kernel(
                    src + sizeof(float),
                    reinterpret_cast<float*>(view->data),
                    view->element_count,
                    scale, zero
                );
                decode_success = true;
            }
            break;
            
        case TensorFormat::Q8_0:
            // Q8 dequantization
            {
                float scale = *reinterpret_cast<const float*>(src);
                Q8_Dequantize_Kernel(
                    src + sizeof(float),
                    reinterpret_cast<float*>(view->data),
                    view->element_count,
                    scale
                );
                decode_success = true;
            }
            break;
            
        case TensorFormat::NANO_2BIT:
            // Nano 2-bit: indices + codebook
            {
                const float* codebook = reinterpret_cast<const float*>(src);
                const uint8_t* indices = src + 16;  // 4-entry codebook = 16 bytes
                
                // Store codebook in view metadata (first 4 floats)
                float* cb = reinterpret_cast<float*>(view->data);
                std::memcpy(cb, codebook, 16);
                
                // Store indices after codebook
                uint8_t* idx = static_cast<uint8_t*>(view->data) + 16;
                std::memcpy(idx, indices, desc.compressed_size - 16);
                
                decode_success = true;
            }
            break;
            
        default:
            last_error_ = "Unsupported tensor format";
            _aligned_free(view->data);
            delete view;
            return nullptr;
    }
    
    if (!decode_success) {
        _aligned_free(view->data);
        delete view;
        return nullptr;
    }
    
    // Update decode time stats
    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
    
    {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        stats_.avg_decode_time_ms = 
            (stats_.avg_decode_time_ms * (stats_.tensors_loaded - 1) + duration.count() / 1000.0) 
            / stats_.tensors_loaded;
    }
    
    return view;
}

void NeuralExecutionVM::ReleaseTensor(ExecutionView* view) {
    if (!view) return;
    
    view->ref_count--;
    
    // If ref_count reaches 0, tensor can be evicted
    // Actual eviction happens in EvictColdTensors()
}

bool NeuralExecutionVM::ExecuteMatMul(const std::string& weight_tensor,
                                       const float* input_activations,
                                       float* output,
                                       uint32_t batch_size,
                                       uint32_t in_features,
                                       uint32_t out_features) {
    // Acquire weight tensor
    ExecutionView* weights = AcquireTensor(weight_tensor);
    if (!weights) {
        return false;
    }
    
    bool success = false;
    
    // Dispatch based on format
    switch (weights->format) {
        case TensorFormat::FP32:
            // Standard FP32 GEMM
            kernel_dispatch_->GEMM_FP32(
                reinterpret_cast<const float*>(weights->data),
                input_activations,
                output,
                batch_size, in_features, out_features
            );
            success = true;
            break;
            
        case TensorFormat::NANO_2BIT:
            // Nano 2-bit kernel
            {
                const float* codebook = reinterpret_cast<const float*>(weights->data);
                const uint8_t* indices = reinterpret_cast<const uint8_t*>(weights->data) + 16;
                
                for (uint32_t b = 0; b < batch_size; ++b) {
                    NanoMatMul_LUT2_Kernel(
                        indices,
                        input_activations + b * in_features,
                        output + b * out_features,
                        codebook,
                        out_features
                    );
                }
                success = true;
            }
            break;
            
        default:
            last_error_ = "Unsupported format for MatMul";
            break;
    }
    
    ReleaseTensor(weights);
    return success;
}

NeuralExecutionVM::Stats NeuralExecutionVM::GetStats() const {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    return stats_;
}

void NeuralExecutionVM::ResetStats() {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    stats_ = {};
}

//============================================================================
// C API Implementation
//============================================================================

extern "C" {

NeuralExecutionVM* NEVM_Create(size_t ram_budget, size_t vram_budget) {
    return new NeuralExecutionVM(ram_budget, vram_budget);
}

void NEVM_Destroy(NeuralExecutionVM* vm) {
    delete vm;
}

int NEVM_LoadModel(NeuralExecutionVM* vm, const wchar_t* path) {
    if (!vm || !path) return -1;
    return vm->LoadModel(path) ? 0 : -1;
}

ExecutionView* NEVM_AcquireTensor(NeuralExecutionVM* vm, const char* name) {
    if (!vm || !name) return nullptr;
    return vm->AcquireTensor(name);
}

void NEVM_ReleaseTensor(NeuralExecutionVM* vm, ExecutionView* view) {
    if (!vm) return;
    vm->ReleaseTensor(view);
}

int NEVM_ExecuteMatMul(NeuralExecutionVM* vm, const char* weight_tensor,
                         const float* input, float* output,
                         uint32_t batch, uint32_t in_f, uint32_t out_f) {
    if (!vm || !weight_tensor || !input || !output) return -1;
    return vm->ExecuteMatMul(weight_tensor, input, output, batch, in_f, out_f) ? 0 : -1;
}

} // extern "C"

} // namespace NEVM
} // namespace RawrXD
