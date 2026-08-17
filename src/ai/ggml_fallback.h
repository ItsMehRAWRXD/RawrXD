#pragma once
// ============================================================================
// GGML Fallback - Dependency-Free Tensor Operations
// Provides minimal tensor/graph APIs when ggml.h is unavailable
// ============================================================================

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <cmath>
#include <vector>
#include <memory>

// ============================================================================
// TYPE DEFINITIONS
// ============================================================================

enum ggml_fallback_type {
    GGML_FALLBACK_TYPE_F32  = 0,
    GGML_FALLBACK_TYPE_F16  = 1,
    GGML_FALLBACK_TYPE_Q4_0 = 2,
    GGML_FALLBACK_TYPE_Q4_1 = 3,
    GGML_FALLBACK_TYPE_Q5_0 = 6,
    GGML_FALLBACK_TYPE_Q5_1 = 7,
    GGML_FALLBACK_TYPE_Q8_0 = 8,
    GGML_FALLBACK_TYPE_Q8_1 = 9,
    GGML_FALLBACK_TYPE_I32  = 10,
    GGML_FALLBACK_TYPE_COUNT
};

enum ggml_fallback_op {
    GGML_FALLBACK_OP_NONE = 0,
    GGML_FALLBACK_OP_DUP,
    GGML_FALLBACK_OP_ADD,
    GGML_FALLBACK_OP_SUB,
    GGML_FALLBACK_OP_MUL,
    GGML_FALLBACK_OP_DIV,
    GGML_FALLBACK_OP_SQR,
    GGML_FALLBACK_OP_SQRT,
    GGML_FALLBACK_OP_SUM,
    GGML_FALLBACK_OP_MEAN,
    GGML_FALLBACK_OP_REPEAT,
    GGML_FALLBACK_OP_ABS,
    GGML_FALLBACK_OP_SGN,
    GGML_FALLBACK_OP_NEG,
    GGML_FALLBACK_OP_STEP,
    GGML_FALLBACK_OP_TANH,
    GGML_FALLBACK_OP_ELU,
    GGML_FALLBACK_OP_RELU,
    GGML_FALLBACK_OP_GELU,
    GGML_FALLBACK_OP_SILU,
    GGML_FALLBACK_OP_SOFT_MAX,
    GGML_FALLBACK_OP_NORM,
    GGML_FALLBACK_OP_RMS_NORM,
    GGML_FALLBACK_OP_MUL_MAT,
    GGML_FALLBACK_OP_SCALE,
    GGML_FALLBACK_OP_CPY,
    GGML_FALLBACK_OP_CONT,
    GGML_FALLBACK_OP_RESHAPE,
    GGML_FALLBACK_OP_VIEW,
    GGML_FALLBACK_OP_PERMUTE,
    GGML_FALLBACK_OP_TRANSPOSE,
    GGML_FALLBACK_OP_GET_ROWS,
    GGML_FALLBACK_OP_DIAG_MASK_INF,
    GGML_FALLBACK_OP_COUNT
};

// ============================================================================
// TENSOR STRUCTURE
// ============================================================================

struct ggml_fallback_tensor {
    ggml_fallback_type type;
    ggml_fallback_op op;
    
    int n_dims;
    int64_t ne[4];  // Number of elements per dimension
    size_t nb[4];   // Stride in bytes per dimension
    
    void* data;
    size_t data_size;
    
    // Source tensors for operations
    ggml_fallback_tensor* src[2];
    
    // Context that owns this tensor
    struct ggml_fallback_context* ctx;
    
    // Gradients (for backward pass)
    ggml_fallback_tensor* grad;
    
    // Additional parameters
    float op_params[4];
    
    ggml_fallback_tensor() 
        : type(GGML_FALLBACK_TYPE_F32)
        , op(GGML_FALLBACK_OP_NONE)
        , n_dims(0)
        , data(nullptr)
        , data_size(0)
        , ctx(nullptr)
        , grad(nullptr) {
        memset(ne, 0, sizeof(ne));
        memset(nb, 0, sizeof(nb));
        memset(src, 0, sizeof(src));
        memset(op_params, 0, sizeof(op_params));
    }
};

// ============================================================================
// CONTEXT STRUCTURE
// ============================================================================

struct ggml_fallback_init_params {
    size_t mem_size;
    void* mem_buffer;
    bool no_alloc;
};

struct ggml_fallback_context {
    std::vector<std::unique_ptr<ggml_fallback_tensor>> tensors;
    std::vector<std::unique_ptr<uint8_t[]>> buffers;
    size_t mem_size;
    size_t mem_used;
    void* mem_buffer;
    bool no_alloc;
    
    explicit ggml_fallback_context(const ggml_fallback_init_params& params)
        : mem_size(params.mem_size)
        , mem_used(0)
        , mem_buffer(params.mem_buffer)
        , no_alloc(params.no_alloc) {}
};

// ============================================================================
// CONTEXT MANAGEMENT
// ============================================================================

inline ggml_fallback_context* ggml_fallback_init(const ggml_fallback_init_params& params) {
    return new ggml_fallback_context(params);
}

inline void ggml_fallback_free(ggml_fallback_context* ctx) {
    delete ctx;
}

inline size_t ggml_fallback_used_mem(const ggml_fallback_context* ctx) {
    return ctx ? ctx->mem_used : 0;
}

// ============================================================================
// TENSOR CREATION
// ============================================================================

inline ggml_fallback_tensor* ggml_fallback_new_tensor_1d(
    ggml_fallback_context* ctx,
    ggml_fallback_type type,
    int64_t ne0) {
    
    if (!ctx) return nullptr;
    
    auto tensor = std::make_unique<ggml_fallback_tensor>();
    tensor->ctx = ctx;
    tensor->type = type;
    tensor->n_dims = 1;
    tensor->ne[0] = ne0;
    tensor->ne[1] = 1;
    tensor->ne[2] = 1;
    tensor->ne[3] = 1;
    
    size_t type_size = sizeof(float);
    if (type == GGML_FALLBACK_TYPE_F16) type_size = sizeof(uint16_t);
    
    tensor->nb[0] = type_size;
    tensor->nb[1] = tensor->nb[0] * ne0;
    tensor->nb[2] = tensor->nb[1];
    tensor->nb[3] = tensor->nb[1];
    
    tensor->data_size = ne0 * type_size;
    
    if (!ctx->no_alloc) {
        tensor->data = new uint8_t[tensor->data_size];
        memset(tensor->data, 0, tensor->data_size);
        ctx->buffers.push_back(std::unique_ptr<uint8_t[]>(static_cast<uint8_t*>(tensor->data)));
    }
    
    auto* ptr = tensor.get();
    ctx->tensors.push_back(std::move(tensor));
    ctx->mem_used += ptr->data_size;
    return ptr;
}

inline ggml_fallback_tensor* ggml_fallback_new_tensor_2d(
    ggml_fallback_context* ctx,
    ggml_fallback_type type,
    int64_t ne0,
    int64_t ne1) {
    
    if (!ctx) return nullptr;
    
    auto tensor = std::make_unique<ggml_fallback_tensor>();
    tensor->ctx = ctx;
    tensor->type = type;
    tensor->n_dims = 2;
    tensor->ne[0] = ne0;
    tensor->ne[1] = ne1;
    tensor->ne[2] = 1;
    tensor->ne[3] = 1;
    
    size_t type_size = sizeof(float);
    if (type == GGML_FALLBACK_TYPE_F16) type_size = sizeof(uint16_t);
    
    tensor->nb[0] = type_size;
    tensor->nb[1] = tensor->nb[0] * ne0;
    tensor->nb[2] = tensor->nb[1] * ne1;
    tensor->nb[3] = tensor->nb[2];
    
    tensor->data_size = ne0 * ne1 * type_size;
    
    if (!ctx->no_alloc) {
        tensor->data = new uint8_t[tensor->data_size];
        memset(tensor->data, 0, tensor->data_size);
        ctx->buffers.push_back(std::unique_ptr<uint8_t[]>(static_cast<uint8_t*>(tensor->data)));
    }
    
    auto* ptr = tensor.get();
    ctx->tensors.push_back(std::move(tensor));
    ctx->mem_used += ptr->data_size;
    return ptr;
}

inline ggml_fallback_tensor* ggml_fallback_new_tensor_3d(
    ggml_fallback_context* ctx,
    ggml_fallback_type type,
    int64_t ne0,
    int64_t ne1,
    int64_t ne2) {
    
    if (!ctx) return nullptr;
    
    auto tensor = std::make_unique<ggml_fallback_tensor>();
    tensor->ctx = ctx;
    tensor->type = type;
    tensor->n_dims = 3;
    tensor->ne[0] = ne0;
    tensor->ne[1] = ne1;
    tensor->ne[2] = ne2;
    tensor->ne[3] = 1;
    
    size_t type_size = sizeof(float);
    if (type == GGML_FALLBACK_TYPE_F16) type_size = sizeof(uint16_t);
    
    tensor->nb[0] = type_size;
    tensor->nb[1] = tensor->nb[0] * ne0;
    tensor->nb[2] = tensor->nb[1] * ne1;
    tensor->nb[3] = tensor->nb[2] * ne2;
    
    tensor->data_size = ne0 * ne1 * ne2 * type_size;
    
    if (!ctx->no_alloc) {
        tensor->data = new uint8_t[tensor->data_size];
        memset(tensor->data, 0, tensor->data_size);
        ctx->buffers.push_back(std::unique_ptr<uint8_t[]>(static_cast<uint8_t*>(tensor->data)));
    }
    
    auto* ptr = tensor.get();
    ctx->tensors.push_back(std::move(tensor));
    ctx->mem_used += ptr->data_size;
    return ptr;
}

inline ggml_fallback_tensor* ggml_fallback_new_tensor_4d(
    ggml_fallback_context* ctx,
    ggml_fallback_type type,
    int64_t ne0,
    int64_t ne1,
    int64_t ne2,
    int64_t ne3) {
    
    if (!ctx) return nullptr;
    
    auto tensor = std::make_unique<ggml_fallback_tensor>();
    tensor->ctx = ctx;
    tensor->type = type;
    tensor->n_dims = 4;
    tensor->ne[0] = ne0;
    tensor->ne[1] = ne1;
    tensor->ne[2] = ne2;
    tensor->ne[3] = ne3;
    
    size_t type_size = sizeof(float);
    if (type == GGML_FALLBACK_TYPE_F16) type_size = sizeof(uint16_t);
    
    tensor->nb[0] = type_size;
    tensor->nb[1] = tensor->nb[0] * ne0;
    tensor->nb[2] = tensor->nb[1] * ne1;
    tensor->nb[3] = tensor->nb[2] * ne2;
    
    tensor->data_size = ne0 * ne1 * ne2 * ne3 * type_size;
    
    if (!ctx->no_alloc) {
        tensor->data = new uint8_t[tensor->data_size];
        memset(tensor->data, 0, tensor->data_size);
        ctx->buffers.push_back(std::unique_ptr<uint8_t[]>(static_cast<uint8_t*>(tensor->data)));
    }
    
    auto* ptr = tensor.get();
    ctx->tensors.push_back(std::move(tensor));
    ctx->mem_used += ptr->data_size;
    return ptr;
}

// ============================================================================
// TENSOR UTILITIES
// ============================================================================

inline size_t ggml_fallback_nbytes(const ggml_fallback_tensor* tensor) {
    if (!tensor) return 0;
    return tensor->data_size;
}

inline size_t ggml_fallback_element_size(const ggml_fallback_tensor* tensor) {
    if (!tensor) return sizeof(float);
    switch (tensor->type) {
        case GGML_FALLBACK_TYPE_F32: return sizeof(float);
        case GGML_FALLBACK_TYPE_F16: return sizeof(uint16_t);
        case GGML_FALLBACK_TYPE_I32: return sizeof(int32_t);
        default: return sizeof(float);
    }
}

inline int64_t ggml_fallback_nelements(const ggml_fallback_tensor* tensor) {
    if (!tensor) return 0;
    return tensor->ne[0] * tensor->ne[1] * tensor->ne[2] * tensor->ne[3];
}

// ============================================================================
// TENSOR OPERATIONS
// ============================================================================

inline ggml_fallback_tensor* ggml_fallback_add(
    ggml_fallback_context* ctx,
    ggml_fallback_tensor* a,
    ggml_fallback_tensor* b) {
    
    if (!ctx || !a || !b) return nullptr;
    
    // Result has same shape as inputs
    auto* result = ggml_fallback_new_tensor_4d(ctx, a->type,
        a->ne[0], a->ne[1], a->ne[2], a->ne[3]);
    
    if (!result) return nullptr;
    
    result->op = GGML_FALLBACK_OP_ADD;
    result->src[0] = a;
    result->src[1] = b;
    
    return result;
}

inline ggml_fallback_tensor* ggml_fallback_mul(
    ggml_fallback_context* ctx,
    ggml_fallback_tensor* a,
    ggml_fallback_tensor* b) {
    
    if (!ctx || !a || !b) return nullptr;
    
    auto* result = ggml_fallback_new_tensor_4d(ctx, a->type,
        a->ne[0], a->ne[1], a->ne[2], a->ne[3]);
    
    if (!result) return nullptr;
    
    result->op = GGML_FALLBACK_OP_MUL;
    result->src[0] = a;
    result->src[1] = b;
    
    return result;
}

inline ggml_fallback_tensor* ggml_fallback_scale(
    ggml_fallback_context* ctx,
    ggml_fallback_tensor* a,
    float s) {
    
    if (!ctx || !a) return nullptr;
    
    auto* result = ggml_fallback_new_tensor_4d(ctx, a->type,
        a->ne[0], a->ne[1], a->ne[2], a->ne[3]);
    
    if (!result) return nullptr;
    
    result->op = GGML_FALLBACK_OP_SCALE;
    result->src[0] = a;
    result->op_params[0] = s;
    
    return result;
}

inline ggml_fallback_tensor* ggml_fallback_silu(
    ggml_fallback_context* ctx,
    ggml_fallback_tensor* a) {
    
    if (!ctx || !a) return nullptr;
    
    auto* result = ggml_fallback_new_tensor_4d(ctx, a->type,
        a->ne[0], a->ne[1], a->ne[2], a->ne[3]);
    
    if (!result) return nullptr;
    
    result->op = GGML_FALLBACK_OP_SILU;
    result->src[0] = a;
    
    return result;
}

inline ggml_fallback_tensor* ggml_fallback_rms_norm(
    ggml_fallback_context* ctx,
    ggml_fallback_tensor* a,
    float eps) {
    
    if (!ctx || !a) return nullptr;
    
    auto* result = ggml_fallback_new_tensor_4d(ctx, a->type,
        a->ne[0], a->ne[1], a->ne[2], a->ne[3]);
    
    if (!result) return nullptr;
    
    result->op = GGML_FALLBACK_OP_RMS_NORM;
    result->src[0] = a;
    result->op_params[0] = eps;
    
    return result;
}

inline ggml_fallback_tensor* ggml_fallback_soft_max(
    ggml_fallback_context* ctx,
    ggml_fallback_tensor* a) {
    
    if (!ctx || !a) return nullptr;
    
    auto* result = ggml_fallback_new_tensor_4d(ctx, a->type,
        a->ne[0], a->ne[1], a->ne[2], a->ne[3]);
    
    if (!result) return nullptr;
    
    result->op = GGML_FALLBACK_OP_SOFT_MAX;
    result->src[0] = a;
    
    return result;
}

inline ggml_fallback_tensor* ggml_fallback_mul_mat(
    ggml_fallback_context* ctx,
    ggml_fallback_tensor* a,
    ggml_fallback_tensor* b) {
    
    if (!ctx || !a || !b) return nullptr;
    
    // Matrix multiplication: result = a * b
    // a: [M, K], b: [K, N], result: [M, N]
    // For 2D tensors
    int64_t ne0 = b->ne[0];  // N
    int64_t ne1 = a->ne[1];  // M
    int64_t ne2 = a->ne[2];
    int64_t ne3 = a->ne[3];
    
    auto* result = ggml_fallback_new_tensor_4d(ctx, GGML_FALLBACK_TYPE_F32,
        ne0, ne1, ne2, ne3);
    
    if (!result) return nullptr;
    
    result->op = GGML_FALLBACK_OP_MUL_MAT;
    result->src[0] = a;
    result->src[1] = b;
    
    return result;
}

inline ggml_fallback_tensor* ggml_fallback_get_rows(
    ggml_fallback_context* ctx,
    ggml_fallback_tensor* a,
    ggml_fallback_tensor* b) {
    
    if (!ctx || !a || !b) return nullptr;
    
    // Get rows from matrix a using indices in b
    auto* result = ggml_fallback_new_tensor_4d(ctx, a->type,
        a->ne[0], b->ne[0], b->ne[1], b->ne[2]);
    
    if (!result) return nullptr;
    
    result->op = GGML_FALLBACK_OP_GET_ROWS;
    result->src[0] = a;
    result->src[1] = b;
    
    return result;
}

inline ggml_fallback_tensor* ggml_fallback_reshape_3d(
    ggml_fallback_context* ctx,
    ggml_fallback_tensor* a,
    int64_t ne0,
    int64_t ne1,
    int64_t ne2) {
    
    if (!ctx || !a) return nullptr;
    
    auto* result = ggml_fallback_new_tensor_3d(ctx, a->type, ne0, ne1, ne2);
    if (!result) return nullptr;
    
    result->op = GGML_FALLBACK_OP_RESHAPE;
    result->src[0] = a;
    
    // Copy data pointer if reshaping
    if (ggml_fallback_nelements(a) == ne0 * ne1 * ne2) {
        result->data = a->data;
        result->data_size = a->data_size;
    }
    
    return result;
}

inline ggml_fallback_tensor* ggml_fallback_permute(
    ggml_fallback_context* ctx,
    ggml_fallback_tensor* a,
    int axis0, int axis1, int axis2, int axis3) {
    
    if (!ctx || !a) return nullptr;
    
    auto* result = ggml_fallback_new_tensor_4d(ctx, a->type,
        a->ne[axis0], a->ne[axis1], a->ne[axis2], a->ne[axis3]);
    
    if (!result) return nullptr;
    
    result->op = GGML_FALLBACK_OP_PERMUTE;
    result->src[0] = a;
    result->op_params[0] = static_cast<float>(axis0);
    result->op_params[1] = static_cast<float>(axis1);
    result->op_params[2] = static_cast<float>(axis2);
    result->op_params[3] = static_cast<float>(axis3);
    
    return result;
}

inline ggml_fallback_tensor* ggml_fallback_cont(
    ggml_fallback_context* ctx,
    ggml_fallback_tensor* a) {
    
    if (!ctx || !a) return nullptr;
    
    auto* result = ggml_fallback_new_tensor_4d(ctx, a->type,
        a->ne[0], a->ne[1], a->ne[2], a->ne[3]);
    
    if (!result) return nullptr;
    
    result->op = GGML_FALLBACK_OP_CONT;
    result->src[0] = a;
    
    return result;
}

// ============================================================================
// COMPUTATION GRAPH
// ============================================================================

struct ggml_fallback_cgraph {
    std::vector<ggml_fallback_tensor*> nodes;
    std::vector<ggml_fallback_tensor*> leafs;
    
    size_t size;
    size_t n_nodes;
    size_t n_leafs;
    
    ggml_fallback_cgraph() : size(0), n_nodes(0), n_leafs(0) {}
};

inline ggml_fallback_cgraph* ggml_fallback_new_graph(ggml_fallback_context* ctx, size_t size) {
    auto* graph = new ggml_fallback_cgraph();
    graph->size = size;
    graph->nodes.reserve(size);
    return graph;
}

inline void ggml_fallback_build_forward_expand(ggml_fallback_cgraph* graph, ggml_fallback_tensor* tensor) {
    if (!graph || !tensor) return;
    if (graph->nodes.size() < graph->size) {
        graph->nodes.push_back(tensor);
        graph->n_nodes++;
    }
}

inline void ggml_fallback_graph_compute(ggml_fallback_context* ctx, ggml_fallback_cgraph* graph);

// ============================================================================
// ALIASES FOR GGML COMPATIBILITY
// ============================================================================

// Map ggml_rxd_* to ggml_fallback_*
#define ggml_rxd_type              ggml_fallback_type
#define ggml_rxd_op                ggml_fallback_op
#define ggml_rxd_tensor            ggml_fallback_tensor
#define ggml_rxd_context           ggml_fallback_context
#define ggml_rxd_init_params       ggml_fallback_init_params
#define ggml_rxd_cgraph            ggml_fallback_cgraph

#define GGML_RXD_TYPE_F32          GGML_FALLBACK_TYPE_F32
#define GGML_RXD_TYPE_F16          GGML_FALLBACK_TYPE_F16
#define GGML_RXD_TYPE_Q4_0         GGML_FALLBACK_TYPE_Q4_0
#define GGML_RXD_TYPE_Q4_1         GGML_FALLBACK_TYPE_Q4_1
#define GGML_RXD_TYPE_Q8_0         GGML_FALLBACK_TYPE_Q8_0
#define GGML_RXD_TYPE_I32          GGML_FALLBACK_TYPE_I32

#define GGML_RXD_OP_ADD            GGML_FALLBACK_OP_ADD
#define GGML_RXD_OP_MUL            GGML_FALLBACK_OP_MUL
#define GGML_RXD_OP_SCALE          GGML_FALLBACK_OP_SCALE
#define GGML_RXD_OP_SILU           GGML_FALLBACK_OP_SILU
#define GGML_RXD_OP_RMS_NORM       GGML_FALLBACK_OP_RMS_NORM
#define GGML_RXD_OP_SOFT_MAX       GGML_FALLBACK_OP_SOFT_MAX
#define GGML_RXD_OP_MUL_MAT        GGML_FALLBACK_OP_MUL_MAT
#define GGML_RXD_OP_GET_ROWS       GGML_FALLBACK_OP_GET_ROWS
#define GGML_RXD_OP_RESHAPE        GGML_FALLBACK_OP_RESHAPE
#define GGML_RXD_OP_PERMUTE        GGML_FALLBACK_OP_PERMUTE
#define GGML_RXD_OP_CONT           GGML_FALLBACK_OP_CONT

#define ggml_rxd_init              ggml_fallback_init
#define ggml_rxd_free              ggml_fallback_free
#define ggml_rxd_used_mem          ggml_fallback_used_mem
#define ggml_rxd_new_tensor_1d     ggml_fallback_new_tensor_1d
#define ggml_rxd_new_tensor_2d     ggml_fallback_new_tensor_2d
#define ggml_rxd_new_tensor_3d     ggml_fallback_new_tensor_3d
#define ggml_rxd_new_tensor_4d     ggml_fallback_new_tensor_4d
#define ggml_rxd_nbytes            ggml_fallback_nbytes
#define ggml_rxd_element_size      ggml_fallback_element_size
#define ggml_rxd_nelements         ggml_fallback_nelements
#define ggml_rxd_add               ggml_fallback_add
#define ggml_rxd_mul               ggml_fallback_mul
#define ggml_rxd_scale             ggml_fallback_scale
#define ggml_rxd_silu              ggml_fallback_silu
#define ggml_rxd_rms_norm          ggml_fallback_rms_norm
#define ggml_rxd_soft_max          ggml_fallback_soft_max
#define ggml_rxd_mul_mat           ggml_fallback_mul_mat
#define ggml_rxd_get_rows          ggml_fallback_get_rows
#define ggml_rxd_reshape_3d        ggml_fallback_reshape_3d
#define ggml_rxd_permute           ggml_fallback_permute
#define ggml_rxd_cont              ggml_fallback_cont
#define ggml_rxd_new_graph         ggml_fallback_new_graph
#define ggml_rxd_build_forward_expand ggml_fallback_build_forward_expand
#define ggml_rxd_graph_compute     ggml_fallback_graph_compute
