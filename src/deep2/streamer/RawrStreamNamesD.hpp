#pragma once
#include "RawrStreamBlocker.hpp"
#include "RawrStreamReceipt.hpp"

static inline const char* RawrBufferKindName(RawrBufferKind v) {
    switch (v) {
        case RAWR_BUFFER_NONE: return "NONE";
        case RAWR_BUFFER_TOKEN_IDS: return "TOKEN_IDS";
        case RAWR_BUFFER_EMBED: return "EMBED";
        case RAWR_BUFFER_HIDDEN_A: return "HIDDEN_A";
        case RAWR_BUFFER_HIDDEN_B: return "HIDDEN_B";
        case RAWR_BUFFER_ATTN_SCRATCH: return "ATTN_SCRATCH";
        case RAWR_BUFFER_FFN_SCRATCH: return "FFN_SCRATCH";
        case RAWR_BUFFER_FINAL_HIDDEN: return "FINAL_HIDDEN";
        case RAWR_BUFFER_LOGITS: return "LOGITS";
        case RAWR_BUFFER_KV_K: return "KV_K";
        case RAWR_BUFFER_KV_V: return "KV_V";
        case RAWR_BUFFER_TENSOR_VIEW: return "TENSOR_VIEW";
        case RAWR_BUFFER_DEVICE_STORAGE: return "DEVICE_STORAGE";
        case RAWR_BUFFER_HOST_STAGING: return "HOST_STAGING";
        default: return "UNKNOWN";
    }
}

static inline const char* RawrTensorAccessName(RawrTensorAccess v) {
    switch (v) {
        case RAWR_ACCESS_NONE: return "NONE";
        case RAWR_ACCESS_HOST_READ: return "HOST_READ";
        case RAWR_ACCESS_HOST_WRITE: return "HOST_WRITE";
        case RAWR_ACCESS_DEVICE_READ: return "DEVICE_READ";
        case RAWR_ACCESS_DEVICE_WRITE: return "DEVICE_WRITE";
        case RAWR_ACCESS_HOST_DEVICE_COPY: return "HOST_DEVICE_COPY";
        case RAWR_ACCESS_EXECUTE: return "EXECUTE";
        default: return "UNKNOWN";
    }
}
