#pragma once

#include "fine_tuner.hpp"
#include <string>

namespace rawrxd::training {

// Simplified model exporter interface
class ModelExporter {
public:
    // Export model to specified format
    static bool exportModel(const FineTuner& trainer,
                            const std::string& output_path,
                            ModelFormat format,
                            QuantizationType quant = QuantizationType::F16);

    // Quick export methods
    static bool exportToGGUF(const FineTuner& trainer,
                              const std::string& output_path,
                              QuantizationType quant = QuantizationType::Q4_0);

    static bool exportToSafetensors(const FineTuner& trainer,
                                     const std::string& output_path);

    static bool exportToONNX(const FineTuner& trainer,
                              const std::string& output_path);

    // Export with metadata
    static bool exportWithMetadata(const FineTuner& trainer,
                                    const std::string& output_path,
                                    ModelFormat format,
                                    const std::string& author,
                                    const std::string& description,
                                    const std::string& license);

    // Merge LoRA before export
    static bool exportMerged(const FineTuner& trainer,
                              const std::string& output_path,
                              ModelFormat format);
};

} // namespace rawrxd::training
