#pragma once
// Streams mapped GGUF tensor ranges directly into compressed resident blocks.
// No full-tensor staging allocation is created by this adapter.
#include "CompressedWeightStore.hpp"
#include "../GGUFLoader.hpp"
#include <cstddef>
#include <cstdint>
#include <string>

namespace rawrxd::compression {

inline bool StoreMappedGGUFTensor(CompressedWeightStore& store,
                                  const Deep2::GGUFTensor& tensor,
                                  std::string* error = nullptr,
                                  bool require_savings = false,
                                  std::size_t max_encoded_bytes =
                                      (std::numeric_limits<std::size_t>::max)()) {
    if (!tensor.data && tensor.sizeBytes != 0) {
        if (error) *error = "GGUF tensor has no mapped/readable data";
        return false;
    }
    // The reader is invoked synchronously by addTensorFromReader. Its context
    // is the mapped tensor pointer, which remains owned by GGUFLoader.
    return store.addTensorFromReader(
        tensor.name, tensor.sizeBytes,
        [](void* context, std::size_t offset, void* destination,
           std::size_t length) -> bool {
            if (length != 0)
                std::memcpy(destination,
                            static_cast<const std::uint8_t*>(context) + offset,
                            length);
            return true;
        },
        const_cast<std::uint8_t*>(tensor.data), error,
        static_cast<std::uint32_t>(tensor.type), require_savings,
        max_encoded_bytes);
}

// Each tensor is published only after all of its blocks pass admission.
// A failure leaves earlier tensors resident; callers can inspect the returned
// count and decide whether to retain or discard that partial model admission.
inline std::size_t StoreMappedGGUFModel(CompressedWeightStore& store,
                                        const Deep2::GGUFLoader& loader,
                                        std::string* failed_tensor = nullptr,
                                        std::string* error = nullptr,
                                        bool require_savings = false) {
    if (!loader.loaded()) {
        if (error) *error = "GGUF loader is not loaded";
        return 0;
    }
    std::size_t stored = 0;
    for (const auto& name : loader.listTensors()) {
        const auto* tensor = loader.getTensor(name);
        if (!tensor || !StoreMappedGGUFTensor(store, *tensor, error,
                                               require_savings)) {
            if (failed_tensor) *failed_tensor = name;
            return stored;
        }
        ++stored;
    }
    return stored;
}

} // namespace rawrxd::compression
