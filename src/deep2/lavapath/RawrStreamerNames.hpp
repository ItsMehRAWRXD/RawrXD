#pragma once
#include "RawrStreamerVocabulary.hpp"

inline const char* RawrStreamStateName(RAWR_U32 v) noexcept {
    static const char* n[] = {
        "COLD", "BOOT", "MODEL_RESOLVE", "MODEL_OPEN", "MODEL_INDEX",
        "MODEL_FACTS", "TOKENIZER_OPEN", "EXEC_CREATE", "CAP_DISCOVER",
        "SPACE_SNAPSHOT", "PLAN", "PREFILL", "DECODE", "EMIT", "COMPLETE",
        "BLOCKED", "FAIL"};
    return v < sizeof(n) / sizeof(n[0]) ? n[v] : "UNKNOWN";
}

inline const char* RawrStreamStatusName(RAWR_U32 v) noexcept {
    static const char* n[] = {"UNKNOWN", "PASS", "OPEN", "BLOCKED", "FAIL",
                              "SKIP", "RETRY", "RECOVERED"};
    return v < sizeof(n) / sizeof(n[0]) ? n[v] : "UNKNOWN";
}

inline const char* RawrStreamStageName(RAWR_U32 v) noexcept {
    static const char* n[] = {
        "NONE", "CLI_PARSE", "ENV_BIND", "MODEL_LOCATE", "GGUF_OPEN",
        "GGUF_INDEX", "TENSOR_INDEX", "ARCH_FACTS", "TOKENIZER_LOAD",
        "EXEC_INSTANCE", "DEVICE_DISCOVER", "CAPABILITY_SOLVE",
        "GEOMETRY_PROBE", "SHADER_VARIANTS", "KERNEL_CANDIDATES",
        "LEGALITY_FILTER", "PARITY_MEASURE", "WINNER_SELECT",
        "PROMPT_TOKENIZE", "EMBED", "PREFILL_LAYER", "DECODE_LAYER",
        "ATTENTION", "Q_PROJ", "K_PROJ", "V_PROJ", "QKV_PROJ", "KVA",
        "O_PROJ", "FFN_GATE", "FFN_UP", "FFN_DOWN", "RMSNORM",
        "FINAL_NORM", "LOGITS", "SAMPLE", "DETOKENIZE", "TOKEN_EMIT",
        "STOP_CHECK", "TEARDOWN"};
    return v < sizeof(n) / sizeof(n[0]) ? n[v] : "UNKNOWN";
}

inline const char* RawrStreamEventName(RAWR_U32 v) noexcept {
    static const char* n[] = {
        "NONE", "RUN_BEGIN", "RUN_READY", "RUN_BLOCKED", "RUN_FAIL",
        "RUN_COMPLETE", "MODEL_FOUND", "MODEL_OPENED", "MODEL_INDEXED",
        "MODEL_FACTS_BOUND", "MODEL_EXEC_CREATED", "TENSOR_DISCOVERED",
        "TENSOR_ADDRESSED", "TENSOR_REGISTERED", "TENSOR_ACQUIRE_BEGIN",
        "TENSOR_ACQUIRE_DONE", "TENSOR_RELEASE", "CAPS_DISCOVERED",
        "SPACE_SNAPSHOT", "SHAPE_LEGAL", "SHAPE_REJECTED", "KERNEL_DISPATCH",
        "KERNEL_PARITY_PASS", "KERNEL_PARITY_FAIL", "KERNEL_MEASURED",
        "KERNEL_WINNER", "PREFILL_BEGIN", "PREFILL_DONE", "DECODE_BEGIN",
        "DECODE_STEP_BEGIN", "DECODE_STEP_DONE", "EMBED_WRITTEN",
        "LAYER_WRITTEN", "FINAL_NORM_WRITTEN", "LOGITS_WRITTEN",
        "TOKEN_SAMPLED", "TOKEN_EMITTED", "STOP_EOS", "STOP_MAX_TOKENS",
        "STOP_USER_CANCEL", "STOP_ERROR"};
    return v < sizeof(n) / sizeof(n[0]) ? n[v] : "UNKNOWN";
}

inline const char* RawrStreamBlockerName(RAWR_U32 v) noexcept {
    static const char* n[] = {
        "NONE", "MODEL_NOT_FOUND", "MODEL_OPEN_FAIL", "GGUF_INVALID",
        "TENSOR_MISSING", "TENSOR_UNADDRESSED", "TENSOR_UNACQUIRED",
        "TOKENIZER_MISSING", "MODEL_FACT_INVALID", "EXEC_INSTANCE_INVALID",
        "NO_DEVICE", "NO_LEGAL_SHAPE", "NO_SHADER_VARIANT", "NO_PARITY_PASS",
        "NO_MEASURE", "NO_WINNER", "EMBED_ZERO", "LAYER_ZERO",
        "FINAL_NORM_ZERO", "LOGITS_ZERO", "SAMPLE_INVALID",
        "MEMORY_PRESSURE", "DEVICE_LOST", "QUEUE_FAIL", "DISPATCH_FAIL",
        "PARITY_FAIL", "TIMEOUT"};
    return v < sizeof(n) / sizeof(n[0]) ? n[v] : "UNKNOWN";
}
