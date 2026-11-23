#pragma once
// Transactional GGUF-to-compressed-residency model owner.
// Source mappings are consumed synchronously during load; the published model
// owns only encoded blocks and bounded decoded-block cache entries.
#include "CompressedWeightStore.hpp"
#include "GGUFCompressedResidency.hpp"
#include "StoredTensorMatvec.hpp"
#include "../GGUFLoader.hpp"
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <memory>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

namespace rawrxd::compression {

class CompressedGGUFModel {
public:
    struct Options {
        std::size_t decoded_cache_bytes = 256u * 1024u * 1024u;
        std::size_t encoded_residency_bytes = (std::numeric_limits<std::size_t>::max)();
        std::size_t block_bytes = CompressedWeightStore::DefaultBlockBytes;
        bool require_savings = false;
    };

    CompressedGGUFModel() = default;
    explicit CompressedGGUFModel(Options options) : options_(options) {}

    CompressedGGUFModel(const CompressedGGUFModel&) = delete;
    CompressedGGUFModel& operator=(const CompressedGGUFModel&) = delete;

    // Build a complete replacement off to the side. The previous model stays
    // live if any tensor fails validation, source reading, or budget admission.
    bool load(const Deep2::GGUFLoader& loader, std::string* error = nullptr,
              std::string* failed_tensor = nullptr) {
        if (!loader.loaded()) {
            if (error) *error = "GGUF loader is not loaded";
            if (failed_tensor) failed_tensor->clear();
            return false;
        }
        std::vector<Deep2::GGUFTensor> tensors;
        const auto names = loader.listTensors();
        tensors.reserve(names.size());
        for (const auto& name : names) {
            const auto* tensor = loader.getTensor(name);
            if (!tensor) {
                if (error) *error = "GGUF tensor disappeared during model admission";
                if (failed_tensor) *failed_tensor = name;
                return false;
            }
            tensors.push_back(*tensor);
        }
        return loadMappedTensors(tensors, error, failed_tensor);
    }

    // Public for deterministic tests and for callers that already own mapped
    // descriptors. The caller's mappings need only remain valid for this call.
    bool loadMappedTensors(const std::vector<Deep2::GGUFTensor>& tensors,
                           std::string* error = nullptr,
                           std::string* failed_tensor = nullptr) {
        if (tensors.empty()) {
            if (error) *error = "cannot publish an empty GGUF model";
            if (failed_tensor) failed_tensor->clear();
            return false;
        }

        auto candidate = std::make_shared<State>();
        try {
            candidate->store = std::make_shared<CompressedWeightStore>(
                options_.decoded_cache_bytes, options_.block_bytes,
                options_.encoded_residency_bytes);
        } catch (const std::exception& ex) {
            if (error) *error = ex.what();
            if (failed_tensor) failed_tensor->clear();
            return false;
        }

        for (const auto& tensor : tensors) {
            try {
                const auto admitted = candidate->store->stats().compressed_bytes;
                if (admitted > options_.encoded_residency_bytes) {
                    if (error) *error = "encoded residency accounting exceeds model budget";
                    if (failed_tensor) *failed_tensor = tensor.name;
                    return false;
                }
                if (!StoreMappedGGUFTensor(*candidate->store, tensor, error,
                                           options_.require_savings,
                                           options_.encoded_residency_bytes -
                                               static_cast<std::size_t>(admitted))) {
                    if (failed_tensor) *failed_tensor = tensor.name;
                    return false;
                }
                TensorInfo info;
                info.type = static_cast<std::uint32_t>(tensor.type);
                info.shape = tensor.shape;
                info.bytes = tensor.sizeBytes;
                candidate->tensors.emplace(tensor.name, std::move(info));
            } catch (const std::exception& ex) {
                if (error) *error = ex.what();
                if (failed_tensor) *failed_tensor = tensor.name;
                return false;
            }
        }

        // Publish one immutable model-state pointer. Existing requests holding
        // the old snapshot remain valid until their last operation completes.
        std::shared_ptr<const State> published = std::move(candidate);
        std::atomic_store_explicit(&state_, std::move(published),
                                   std::memory_order_release);
        if (error) error->clear();
        if (failed_tensor) failed_tensor->clear();
        return true;
    }

    void unload() noexcept {
        std::shared_ptr<const State> empty;
        std::atomic_store_explicit(&state_, std::move(empty),
                                   std::memory_order_release);
    }

    bool loaded() const noexcept { return static_cast<bool>(snapshot()); }

    std::size_t tensorCount() const noexcept {
        const auto state = snapshot();
        return state ? state->tensors.size() : 0;
    }

    bool contains(const std::string& name) const {
        const auto state = snapshot();
        return state && state->tensors.find(name) != state->tensors.end();
    }

    StoreStats stats() const {
        const auto state = snapshot();
        return state ? state->store->stats() : StoreStats{};
    }

    bool readTensorRange(const std::string& name, std::size_t offset,
                         void* destination, std::size_t length,
                         std::string* error = nullptr) const {
        const auto state = snapshot();
        if (!state) {
            if (error) *error = "no compressed GGUF model is loaded";
            return false;
        }
        if (state->tensors.find(name) == state->tensors.end()) {
            if (error) *error = "unknown tensor";
            return false;
        }
        return state->store->readRange(name, offset, destination, length, error);
    }

    // Matrix-vector inference entry point for 2-D F32, F16 and Q8_0 GGUF
    // tensors. GGUF dimension order is [input columns, output rows].
    bool matvec(const std::string& name, const float* input, float* output,
                std::size_t staging_bytes = 64u * 1024u,
                std::string* error = nullptr) const {
        const auto state = snapshot();
        if (!state) {
            if (error) *error = "no compressed GGUF model is loaded";
            return false;
        }
        const auto found = state->tensors.find(name);
        if (found == state->tensors.end()) {
            if (error) *error = "unknown tensor";
            return false;
        }
        const auto& info = found->second;
        if (info.shape.size() != 2 || info.shape[0] <= 0 || info.shape[1] <= 0) {
            if (error) *error = "resident matvec requires a two-dimensional tensor";
            return false;
        }
        const auto cols = static_cast<std::uint64_t>(info.shape[0]);
        const auto rows = static_cast<std::uint64_t>(info.shape[1]);
        if (cols > (std::numeric_limits<std::size_t>::max)() ||
            rows > (std::numeric_limits<std::size_t>::max)()) {
            if (error) *error = "tensor dimensions exceed host address space";
            return false;
        }
        ResidentWeightType type;
        switch (info.type) {
            case GGML_TYPE_F32: type = ResidentWeightType::F32; break;
            case GGML_TYPE_F16: type = ResidentWeightType::F16; break;
            case 8u: type = ResidentWeightType::Q8_0; break;
            default:
                if (error) *error = "no resident matvec kernel for this GGML type";
                return false;
        }
        try {
            StoredTensorMatvec(*state->store, name, type, input, output,
                                static_cast<std::size_t>(rows),
                                static_cast<std::size_t>(cols), staging_bytes);
            if (error) error->clear();
            return true;
        } catch (const std::exception& ex) {
            if (error) *error = ex.what();
            return false;
        }
    }

private:
    struct TensorInfo {
        std::uint32_t type = GGML_TYPE_OPAQUE;
        std::vector<std::int64_t> shape;
        std::size_t bytes = 0;
    };
    struct State {
        std::shared_ptr<CompressedWeightStore> store;
        std::unordered_map<std::string, TensorInfo> tensors;
    };

    std::shared_ptr<const State> snapshot() const noexcept {
        return std::atomic_load_explicit(&state_, std::memory_order_acquire);
    }

    Options options_{};
    mutable std::shared_ptr<const State> state_;
};

} // namespace rawrxd::compression
