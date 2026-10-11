// ggml_link_stubs.cpp
// Minimal link stubs for ggml symbols the runtime-dispatch binary references
// (from ggml.c) but never calls on the exercised path. Signatures match
// ggml-backend.h exactly. Nothing here is invoked during inference.
#include "ggml-backend.h"
#include "ggml.h"
#include <cstdlib>
#include <cstring>

extern "C" {

void ggml_backend_tensor_memset(struct ggml_tensor* tensor, uint8_t value,
                                size_t offset, size_t size) {
    if (tensor && tensor->data) {
        std::memset(static_cast<char*>(tensor->data) + offset, value, size);
    }
}

void ggml_backend_tensor_set(struct ggml_tensor* tensor, const void* data,
                             size_t offset, size_t size) {
    if (tensor && tensor->data && data) {
        std::memcpy(static_cast<char*>(tensor->data) + offset, data, size);
    }
}

void ggml_backend_tensor_get(const struct ggml_tensor* tensor, void* data,
                             size_t offset, size_t size) {
    if (tensor && tensor->data && data) {
        std::memcpy(data, static_cast<const char*>(tensor->data) + offset, size);
    }
}

void ggml_backend_buffer_free(ggml_backend_buffer_t buffer) { (void)buffer; }

void* ggml_backend_buffer_get_base(ggml_backend_buffer_t buffer) {
    (void)buffer; return nullptr;
}

size_t ggml_backend_buffer_get_size(ggml_backend_buffer_t buffer) {
    (void)buffer; return 0;
}

enum ggml_status ggml_backend_buffer_init_tensor(ggml_backend_buffer_t buffer,
                                                  struct ggml_tensor* tensor) {
    (void)buffer; (void)tensor; return GGML_STATUS_SUCCESS;
}

size_t ggml_backend_buffer_get_alignment(ggml_backend_buffer_t buffer) {
    (void)buffer; return 32;
}

size_t ggml_backend_buffer_get_max_size(ggml_backend_buffer_t buffer) {
    (void)buffer; return 0;
}

size_t ggml_backend_buffer_get_alloc_size(ggml_backend_buffer_t buffer,
                                          const struct ggml_tensor* tensor) {
    (void)buffer; (void)tensor; return 0;
}

void ggml_backend_buffer_clear(ggml_backend_buffer_t buffer, uint8_t value) {
    (void)buffer; (void)value;
}

void ggml_backend_synchronize(ggml_backend_t backend) { (void)backend; }

void ggml_critical_section_start(void) {}
void ggml_critical_section_end(void) {}

} // extern "C"
