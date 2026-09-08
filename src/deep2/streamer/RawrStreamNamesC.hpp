#pragma once
#include "RawrStreamEvent.hpp"
#include "RawrStreamBlocker.hpp"

static inline const char* RawrStreamEventName(RawrStreamEvent v) {
    switch (v) {
        case RAWR_EVENT_NONE: return "NONE";
        case RAWR_EVENT_RUN_BEGIN: return "RUN_BEGIN";
        case RAWR_EVENT_RUN_READY: return "RUN_READY";
        case RAWR_EVENT_RUN_BLOCKED: return "RUN_BLOCKED";
        case RAWR_EVENT_RUN_FAIL: return "RUN_FAIL";
        case RAWR_EVENT_RUN_COMPLETE: return "RUN_COMPLETE";
        case RAWR_EVENT_MODEL_FOUND: return "MODEL_FOUND";
        case RAWR_EVENT_MODEL_OPENED: return "MODEL_OPENED";
        case RAWR_EVENT_MODEL_INDEXED: return "MODEL_INDEXED";
        case RAWR_EVENT_MODEL_FACTS_BOUND: return "MODEL_FACTS_BOUND";
        case RAWR_EVENT_MODEL_EXEC_CREATED: return "MODEL_EXEC_CREATED";
        case RAWR_EVENT_TENSOR_DISCOVERED: return "TENSOR_DISCOVERED";
        case RAWR_EVENT_TENSOR_ADDRESSED: return "TENSOR_ADDRESSED";
        case RAWR_EVENT_TENSOR_REGISTERED: return "TENSOR_REGISTERED";
        case RAWR_EVENT_TENSOR_ACQUIRE_BEGIN: return "TENSOR_ACQUIRE_BEGIN";
        case RAWR_EVENT_TENSOR_ACQUIRE_DONE: return "TENSOR_ACQUIRE_DONE";
        case RAWR_EVENT_TENSOR_RELEASE: return "TENSOR_RELEASE";
        case RAWR_EVENT_CAPS_DISCOVERED: return "CAPS_DISCOVERED";
        case RAWR_EVENT_SPACE_SNAPSHOT: return "SPACE_SNAPSHOT";
        case RAWR_EVENT_SHAPE_LEGAL: return "SHAPE_LEGAL";
        case RAWR_EVENT_SHAPE_REJECTED: return "SHAPE_REJECTED";
        case RAWR_EVENT_KERNEL_DISPATCH: return "KERNEL_DISPATCH";
        case RAWR_EVENT_KERNEL_PARITY_PASS: return "KERNEL_PARITY_PASS";
        case RAWR_EVENT_KERNEL_PARITY_FAIL: return "KERNEL_PARITY_FAIL";
        case RAWR_EVENT_KERNEL_MEASURED: return "KERNEL_MEASURED";
        case RAWR_EVENT_KERNEL_WINNER: return "KERNEL_WINNER";
        case RAWR_EVENT_PREFILL_BEGIN: return "PREFILL_BEGIN";
        case RAWR_EVENT_PREFILL_DONE: return "PREFILL_DONE";
        case RAWR_EVENT_DECODE_BEGIN: return "DECODE_BEGIN";
        case RAWR_EVENT_DECODE_STEP_BEGIN: return "DECODE_STEP_BEGIN";
        case RAWR_EVENT_DECODE_STEP_DONE: return "DECODE_STEP_DONE";
        case RAWR_EVENT_EMBED_WRITTEN: return "EMBED_WRITTEN";
        case RAWR_EVENT_LAYER_WRITTEN: return "LAYER_WRITTEN";
        case RAWR_EVENT_FINAL_NORM_WRITTEN: return "FINAL_NORM_WRITTEN";
        case RAWR_EVENT_LOGITS_WRITTEN: return "LOGITS_WRITTEN";
        case RAWR_EVENT_TOKEN_SAMPLED: return "TOKEN_SAMPLED";
        case RAWR_EVENT_TOKEN_EMITTED: return "TOKEN_EMITTED";
        case RAWR_EVENT_STOP_EOS: return "STOP_EOS";
        case RAWR_EVENT_STOP_MAX_TOKENS: return "STOP_MAX_TOKENS";
        case RAWR_EVENT_STOP_USER_CANCEL: return "STOP_USER_CANCEL";
        case RAWR_EVENT_STOP_ERROR: return "STOP_ERROR";
        default: return "UNKNOWN";
    }
}

static inline const char* RawrStreamBlockerName(RawrStreamBlocker v) {
    switch (v) {
        case RAWR_BLOCK_NONE: return "NONE";
        case RAWR_BLOCK_MODEL_NOT_FOUND: return "MODEL_NOT_FOUND";
        case RAWR_BLOCK_MODEL_OPEN_FAIL: return "MODEL_OPEN_FAIL";
        case RAWR_BLOCK_GGUF_INVALID: return "GGUF_INVALID";
        case RAWR_BLOCK_TENSOR_MISSING: return "TENSOR_MISSING";
        case RAWR_BLOCK_TENSOR_UNADDRESSED: return "TENSOR_UNADDRESSED";
        case RAWR_BLOCK_TENSOR_UNACQUIRED: return "TENSOR_UNACQUIRED";
        case RAWR_BLOCK_TOKENIZER_MISSING: return "TOKENIZER_MISSING";
        case RAWR_BLOCK_MODEL_FACT_INVALID: return "MODEL_FACT_INVALID";
        case RAWR_BLOCK_EXEC_INSTANCE_INVALID: return "EXEC_INSTANCE_INVALID";
        case RAWR_BLOCK_NO_DEVICE: return "NO_DEVICE";
        case RAWR_BLOCK_NO_LEGAL_SHAPE: return "NO_LEGAL_SHAPE";
        case RAWR_BLOCK_NO_SHADER_VARIANT: return "NO_SHADER_VARIANT";
        case RAWR_BLOCK_NO_PARITY_PASS: return "NO_PARITY_PASS";
        case RAWR_BLOCK_NO_MEASURE: return "NO_MEASURE";
        case RAWR_BLOCK_NO_WINNER: return "NO_WINNER";
        case RAWR_BLOCK_EMBED_ZERO: return "EMBED_ZERO";
        case RAWR_BLOCK_LAYER_ZERO: return "LAYER_ZERO";
        case RAWR_BLOCK_FINAL_NORM_ZERO: return "FINAL_NORM_ZERO";
        case RAWR_BLOCK_LOGITS_ZERO: return "LOGITS_ZERO";
        case RAWR_BLOCK_SAMPLE_INVALID: return "SAMPLE_INVALID";
        case RAWR_BLOCK_MEMORY_PRESSURE: return "MEMORY_PRESSURE";
        case RAWR_BLOCK_DEVICE_LOST: return "DEVICE_LOST";
        case RAWR_BLOCK_QUEUE_FAIL: return "QUEUE_FAIL";
        case RAWR_BLOCK_DISPATCH_FAIL: return "DISPATCH_FAIL";
        case RAWR_BLOCK_PARITY_FAIL: return "PARITY_FAIL";
        case RAWR_BLOCK_TIMEOUT: return "TIMEOUT";
        default: return "UNKNOWN";
    }
}
