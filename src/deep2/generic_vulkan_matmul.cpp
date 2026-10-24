#include "generic_vulkan_matmul.hpp"

#include <algorithm>
#include <limits>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

#include "ggml-backend.h"
#include "ggml-vulkan.h"

namespace RawrXD::Deep2::GenericVulkan {
namespace {

struct BackendSlot {
    ggml_backend_t backend = nullptr;
};

struct MatVecWorkspace {
    ggml_backend_t backend = nullptr;
    ggml_context* context = nullptr;
    ggml_backend_buffer_t buffer = nullptr;
    ggml_tensor* weight = nullptr;
    ggml_tensor* activation = nullptr;
    ggml_tensor* result = nullptr;
    ggml_cgraph* graph = nullptr;
    // GGUF tensor payloads are memory-mapped and immutable for the lifetime of
    // an executor.  Keep the last source identity so decode does not upload the
    // same weight matrix again on every token.
    const void* resident_source = nullptr;
    size_t resident_bytes = 0;
    bool resident = false;
    std::mutex mutex;

    ~MatVecWorkspace() {
        if (buffer) ggml_backend_buffer_free(buffer);
        if (context) ggml_free(context);
    }
};

struct BatchWorkspace {
    ggml_backend_t backend = nullptr;
    ggml_context* context = nullptr;
    ggml_backend_buffer_t buffer = nullptr;
    std::vector<ggml_tensor*> weights;
    std::vector<ggml_tensor*> activations;
    std::vector<ggml_tensor*> results;
    std::vector<const void*> resident_sources;
    std::vector<size_t> resident_bytes;
    std::vector<bool> resident;
    ggml_cgraph* graph = nullptr;
    std::mutex mutex;

    ~BatchWorkspace() {
        if (buffer) ggml_backend_buffer_free(buffer);
        if (context) ggml_free(context);
    }
};

std::mutex g_mutex;
std::unordered_map<int32_t, BackendSlot> g_backends;
std::unordered_map<std::string, std::shared_ptr<MatVecWorkspace>> g_workspaces;
std::unordered_map<std::string, std::shared_ptr<BatchWorkspace>> g_batch_workspaces;

ggml_backend_t BackendFor(int32_t device) {
    if (device < 0) device = 0;
    auto it = g_backends.find(device);
    if (it != g_backends.end()) return it->second.backend;
    if (device >= ggml_backend_vk_get_device_count()) return nullptr;
    ggml_backend_t backend = ggml_backend_vk_init(static_cast<size_t>(device));
    if (!backend) return nullptr;
    g_backends.emplace(device, BackendSlot{backend});
    return backend;
}

bool CheckedProduct(size_t a, size_t b, size_t& out) {
    if (a != 0 && b > std::numeric_limits<size_t>::max() / a) return false;
    out = a * b;
    return true;
}

std::shared_ptr<MatVecWorkspace> CreateWorkspace(ggml_backend_t backend,
                                                  ggml_type type,
                                                  size_t rows,
                                                  size_t cols) {
    ggml_init_params params{};
    params.mem_size = ggml_tensor_overhead() * 3 + ggml_graph_overhead();
    params.no_alloc = true;
    ggml_context* context = ggml_init(params);
    if (!context) return {};

    auto workspace = std::make_shared<MatVecWorkspace>();
    workspace->backend = backend;
    workspace->context = context;
    workspace->weight = ggml_new_tensor_2d(context, type,
                                           static_cast<int64_t>(cols),
                                           static_cast<int64_t>(rows));
    workspace->activation = ggml_new_tensor_2d(context, GGML_TYPE_F32,
                                               static_cast<int64_t>(cols), 1);
    if (!workspace->weight || !workspace->activation) return {};

    workspace->result = ggml_mul_mat(context, workspace->weight,
                                     workspace->activation);
    if (!workspace->result) return {};
    workspace->buffer = ggml_backend_alloc_ctx_tensors(context, backend);
    if (!workspace->buffer) return {};
    workspace->graph = ggml_new_graph(context);
    if (!workspace->graph) return {};
    ggml_build_forward_expand(workspace->graph, workspace->result);
    return workspace;
}

std::shared_ptr<BatchWorkspace> CreateBatchWorkspace(ggml_backend_t backend,
                                                      ggml_type type,
                                                      size_t count,
                                                      size_t rows,
                                                      size_t cols) {
    ggml_init_params params{};
    params.mem_size = ggml_tensor_overhead() * (3 * count) +
                      ggml_graph_overhead();
    params.no_alloc = true;
    ggml_context* context = ggml_init(params);
    if (!context) return {};

    auto workspace = std::make_shared<BatchWorkspace>();
    workspace->backend = backend;
    workspace->context = context;
    workspace->weights.reserve(count);
    workspace->activations.reserve(count);
    workspace->results.reserve(count);
    workspace->resident_sources.assign(count, nullptr);
    workspace->resident_bytes.assign(count, 0);
    workspace->resident.assign(count, false);
    for (size_t i = 0; i < count; ++i) {
        ggml_tensor* weight = ggml_new_tensor_2d(context, type,
                                                 static_cast<int64_t>(cols),
                                                 static_cast<int64_t>(rows));
        ggml_tensor* activation = ggml_new_tensor_2d(context, GGML_TYPE_F32,
                                                     static_cast<int64_t>(cols), 1);
        if (!weight || !activation) return {};
        ggml_tensor* result = ggml_mul_mat(context, weight, activation);
        if (!result) return {};
        workspace->weights.push_back(weight);
        workspace->activations.push_back(activation);
        workspace->results.push_back(result);
    }
    workspace->buffer = ggml_backend_alloc_ctx_tensors(context, backend);
    if (!workspace->buffer) return {};
    workspace->graph = ggml_new_graph(context);
    if (!workspace->graph) return {};
    for (ggml_tensor* result : workspace->results)
        ggml_build_forward_expand(workspace->graph, result);
    return workspace;
}

}  // namespace

bool MatVec(int32_t device,
            ggml_type type,
            const void* weights,
            size_t weight_bytes,
            size_t rows,
            size_t cols,
            const float* input,
            float* output) {
    if (!weights || !input || !output || rows == 0 || cols == 0) return false;
    if (type != GGML_TYPE_IQ2_S && type != GGML_TYPE_MXFP4) return false;

    const size_t row_bytes = ggml_row_size(type, cols);
    size_t required = 0;
    if (row_bytes == 0 || !CheckedProduct(row_bytes, rows, required) ||
        weight_bytes < required) {
        return false;
    }
    if (ggml_blck_size(type) <= 0 || cols % static_cast<size_t>(ggml_blck_size(type)) != 0) {
        return false;
    }

    const int32_t normalized_device = device < 0 ? 0 : device;
    const std::string key = std::to_string(normalized_device) + ":" +
                            std::to_string(static_cast<int>(type)) + ":" +
                            std::to_string(rows) + ":" + std::to_string(cols);
    std::shared_ptr<MatVecWorkspace> workspace;
    {
        std::lock_guard<std::mutex> lock(g_mutex);
        ggml_backend_t backend = BackendFor(normalized_device);
        if (!backend) return false;
        auto it = g_workspaces.find(key);
        if (it == g_workspaces.end()) {
            workspace = CreateWorkspace(backend, type, rows, cols);
            if (!workspace) return false;
            g_workspaces.emplace(key, workspace);
        } else {
            workspace = it->second;
        }
    }

    std::lock_guard<std::mutex> workspace_lock(workspace->mutex);
    if (!workspace->resident || workspace->resident_source != weights ||
        workspace->resident_bytes != required) {
        ggml_backend_tensor_set(workspace->weight, weights, 0, required);
        workspace->resident_source = weights;
        workspace->resident_bytes = required;
        workspace->resident = true;
    }
    ggml_backend_tensor_set(workspace->activation, input, 0,
                            cols * sizeof(float));
    if (ggml_backend_graph_compute(workspace->backend, workspace->graph) !=
        GGML_STATUS_SUCCESS) {
        return false;
    }
    ggml_backend_synchronize(workspace->backend);
    ggml_backend_tensor_get(workspace->result, output, 0,
                            rows * sizeof(float));
    return true;
}

bool MatVecBatch(int32_t device,
                 ggml_type type,
                 const MatVecSlice* slices,
                 size_t count,
                 size_t rows,
                 size_t cols,
                 const float* inputs,
                 size_t input_stride,
                 float* outputs,
                 size_t output_stride) {
    if (!slices || count == 0 || !inputs || !outputs || rows == 0 || cols == 0)
        return false;
    if (type != GGML_TYPE_IQ2_S && type != GGML_TYPE_MXFP4)
        return false;
    if (ggml_blck_size(type) <= 0 ||
        cols % static_cast<size_t>(ggml_blck_size(type)) != 0)
        return false;

    const size_t row_bytes = ggml_row_size(type, cols);
    size_t required = 0;
    if (row_bytes == 0 || !CheckedProduct(row_bytes, rows, required)) return false;
    for (size_t i = 0; i < count; ++i) {
        if (!slices[i].weights || slices[i].weight_bytes < required)
            return false;
    }

    const int32_t normalized_device = device < 0 ? 0 : device;
    const std::string key = "batch:" + std::to_string(normalized_device) + ":" +
                            std::to_string(static_cast<int>(type)) + ":" +
                            std::to_string(count) + ":" + std::to_string(rows) +
                            ":" + std::to_string(cols);
    std::shared_ptr<BatchWorkspace> workspace;
    {
        std::lock_guard<std::mutex> lock(g_mutex);
        ggml_backend_t backend = BackendFor(normalized_device);
        if (!backend) return false;
        auto it = g_batch_workspaces.find(key);
        if (it == g_batch_workspaces.end()) {
            workspace = CreateBatchWorkspace(backend, type, count, rows, cols);
            if (!workspace) return false;
            g_batch_workspaces.emplace(key, workspace);
        } else {
            workspace = it->second;
        }
    }

    std::lock_guard<std::mutex> workspace_lock(workspace->mutex);
    for (size_t i = 0; i < count; ++i) {
        if (!workspace->resident[i] ||
            workspace->resident_sources[i] != slices[i].weights ||
            workspace->resident_bytes[i] != required) {
            ggml_backend_tensor_set(workspace->weights[i], slices[i].weights,
                                    0, required);
            workspace->resident_sources[i] = slices[i].weights;
            workspace->resident_bytes[i] = required;
            workspace->resident[i] = true;
        }
        const float* input = input_stride == 0
            ? inputs : inputs + i * input_stride;
        ggml_backend_tensor_set(workspace->activations[i], input, 0,
                                cols * sizeof(float));
    }
    if (ggml_backend_graph_compute(workspace->backend, workspace->graph) !=
        GGML_STATUS_SUCCESS)
        return false;
    ggml_backend_synchronize(workspace->backend);
    const size_t stride = output_stride == 0 ? rows : output_stride;
    for (size_t i = 0; i < count; ++i) {
        ggml_backend_tensor_get(workspace->results[i],
                                outputs + i * stride, 0,
                                rows * sizeof(float));
    }
    return true;
}

}  // namespace RawrXD::Deep2::GenericVulkan
