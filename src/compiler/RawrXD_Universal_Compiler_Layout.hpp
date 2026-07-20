/**=============================================================================
 * RawrXD_Universal_Compiler_Layout.hpp
 * Compiler Extension for NHWC Layout Support
 * 
 * Adds --layout=nhwc flag to the RawrXD Universal Compiler
 *=============================================================================*/

#ifndef RAWRXD_UNIVERSAL_COMPILER_LAYOUT_HPP
#define RAWRXD_UNIVERSAL_COMPILER_LAYOUT_HPP

#include "RawrXD_TensorLayout_NHWC.hpp"
#include <string>
#include <vector>
#include <fstream>

namespace RawrXD {
namespace Compiler {

/**=============================================================================
 * Layout Configuration
 *=============================================================================*/
enum class LayoutFormat {
    NCHW,       // Standard planar layout
    NHWC,       // Interleaved layout (optimal for inference)
    RAWH        // RawrXD optimized (NHWC + custom alignment)
};

struct LayoutConfig {
    LayoutFormat format = LayoutFormat::NCHW;
    bool auto_convert = false;      // Convert during compilation
    bool validate = true;           // Validate conversion correctness
    int alignment = 64;             // AVX-512 alignment
    
    bool IsNHWC() const {
        return format == LayoutFormat::NHWC || format == LayoutFormat::RAWH;
    }
};

/**=============================================================================
 * Model Tensor Descriptor
 *=============================================================================*/
struct ModelTensorDesc {
    std::string name;           // Tensor name (e.g., "attention.wq")
    int shape[4];               // [N, C, H, W] or [N, H, W, C]
    uint32_t data_type;         // 0=f32, 1=q4_0, 2=q8_0
    size_t offset;              // Offset in file
    size_t size;                // Size in bytes
    LayoutFormat source_layout;
    LayoutFormat target_layout;
};

/**=============================================================================
 * Layout-Aware Model Compiler
 * 
 * Integrates NHWC conversion into the model compilation pipeline
 *=============================================================================*/
class LayoutAwareModelCompiler {
public:
    LayoutAwareModelCompiler(const LayoutConfig& config) 
        : config_(config) {}
    
    /**=========================================================================
     * Compile model with layout transformation
     * 
     * @param input_path Path to input GGUF model
     * @param output_path Path to output compiled model
     * @return true on success, false on failure
     *=========================================================================*/
    bool CompileModel(
        const std::string& input_path,
        const std::string& output_path
    ) {
        // Step 1: Parse input model
        if (!ParseInputModel(input_path)) {
            return false;
        }
        
        // Step 2: Calculate output sizes
        CalculateOutputSizes();
        
        // Step 3: Convert tensors to NHWC if needed
        if (config_.IsNHWC()) {
            if (!ConvertTensorsToNHWC()) {
                return false;
            }
        }
        
        // Step 4: Write output model
        if (!WriteOutputModel(output_path)) {
            return false;
        }
        
        return true;
    }
    
    /**=========================================================================
     * Get compilation statistics
     *=========================================================================*/
    struct CompileStats {
        size_t tensors_converted = 0;
        size_t tensors_unchanged = 0;
        size_t bytes_converted = 0;
        double conversion_time_ms = 0.0;
        
        void Print() const {
            printf("Layout Conversion Statistics:\n");
            printf("  Tensors converted: %zu\n", tensors_converted);
            printf("  Tensors unchanged: %zu\n", tensors_unchanged);
            printf("  Bytes converted: %.2f MB\n", bytes_converted / (1024.0 * 1024.0));
            printf("  Conversion time: %.2f ms\n", conversion_time_ms);
        }
    };
    
    const CompileStats& GetStats() const { return stats_; }

private:
    LayoutConfig config_;
    CompileStats stats_;
    std::vector<ModelTensorDesc> tensors_;
    std::vector<std::vector<uint8_t>> converted_data_;
    
    bool ParseInputModel(const std::string& path) {
        // TODO: Integrate with existing GGUF loader
        // For now, placeholder that would be filled by actual GGUF parsing
        return true;
    }
    
    void CalculateOutputSizes() {
        for (auto& tensor : tensors_) {
            if (config_.IsNHWC() && tensor.source_layout == LayoutFormat::NCHW) {
                // Calculate new size for NHWC layout
                tensor.size = Memory::RawrXD_CalculateNHWCSize(
                    tensor.shape[0], tensor.shape[1], tensor.shape[2], tensor.shape[3],
                    tensor.data_type
                );
                tensor.target_layout = config_.format;
            } else {
                tensor.target_layout = tensor.source_layout;
            }
        }
    }
    
    bool ConvertTensorsToNHWC() {
        auto start_time = std::chrono::high_resolution_clock::now();
        
        converted_data_.reserve(tensors_.size());
        
        for (size_t i = 0; i < tensors_.size(); ++i) {
            auto& tensor = tensors_[i];
            
            if (tensor.source_layout == LayoutFormat::NCHW && config_.IsNHWC()) {
                // Allocate converted buffer
                converted_data_.emplace_back(tensor.size);
                void* dst = converted_data_.back().data();
                
                // Perform conversion
                // Note: src would come from loaded GGUF data
                int result = Memory::RawrXD_ConvertLayout_NCHWtoNHWC(
                    nullptr,  // Would be actual tensor data
                    dst,
                    tensor.shape[0], tensor.shape[1], tensor.shape[2], tensor.shape[3],
                    tensor.data_type
                );
                
                if (result != 0) {
                    return false;
                }
                
                stats_.tensors_converted++;
                stats_.bytes_converted += tensor.size;
            } else {
                stats_.tensors_unchanged++;
                converted_data_.emplace_back();  // Empty placeholder
            }
        }
        
        auto end_time = std::chrono::high_resolution_clock::now();
        stats_.conversion_time_ms = std::chrono::duration<double, std::milli>(
            end_time - start_time
        ).count();
        
        return true;
    }
    
    bool WriteOutputModel(const std::string& path) {
        // TODO: Integrate with existing model writer
        // Write layout headers and converted data
        return true;
    }
};

/**=============================================================================
 * Command Line Parser
 *=============================================================================*/
class LayoutCommandLineParser {
public:
    static LayoutConfig Parse(int argc, char** argv) {
        LayoutConfig config;
        
        for (int i = 1; i < argc; ++i) {
            std::string arg = argv[i];
            
            if (arg == "--layout=nchw" || arg == "--layout=NCHW") {
                config.format = LayoutFormat::NCHW;
                config.auto_convert = false;
            } else if (arg == "--layout=nhwc" || arg == "--layout=NHWC") {
                config.format = LayoutFormat::NHWC;
                config.auto_convert = true;
            } else if (arg == "--layout=rawh" || arg == "--layout=RAWH") {
                config.format = LayoutFormat::RAWH;
                config.auto_convert = true;
            } else if (arg == "--no-validate") {
                config.validate = false;
            } else if (arg.find("--alignment=") == 0) {
                config.alignment = std::stoi(arg.substr(12));
            }
        }
        
        return config;
    }
    
    static void PrintHelp() {
        printf("Layout Options:\n");
        printf("  --layout=nchw    Use NCHW layout (default)\n");
        printf("  --layout=nhwc    Convert to NHWC layout (optimal for inference)\n");
        printf("  --layout=rawh    Use RawrXD optimized layout\n");
        printf("  --no-validate    Skip conversion validation\n");
        printf("  --alignment=N    Set alignment (default: 64)\n");
    }
};

} // namespace Compiler
} // namespace RawrXD

#endif // RAWRXD_UNIVERSAL_COMPILER_LAYOUT_HPP
