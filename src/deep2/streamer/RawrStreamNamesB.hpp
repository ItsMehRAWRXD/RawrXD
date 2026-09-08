#pragma once
#include "RawrStreamStage.hpp"

static inline const char* RawrStreamStageName(RawrStreamStage v) {
    switch (v) {
        case RAWR_STAGE_NONE: return "NONE";
        case RAWR_STAGE_CLI_PARSE: return "CLI_PARSE";
        case RAWR_STAGE_ENV_BIND: return "ENV_BIND";
        case RAWR_STAGE_MODEL_LOCATE: return "MODEL_LOCATE";
        case RAWR_STAGE_GGUF_OPEN: return "GGUF_OPEN";
        case RAWR_STAGE_GGUF_INDEX: return "GGUF_INDEX";
        case RAWR_STAGE_TENSOR_INDEX: return "TENSOR_INDEX";
        case RAWR_STAGE_ARCH_FACTS: return "ARCH_FACTS";
        case RAWR_STAGE_TOKENIZER_LOAD: return "TOKENIZER_LOAD";
        case RAWR_STAGE_EXEC_INSTANCE: return "EXEC_INSTANCE";
        case RAWR_STAGE_DEVICE_DISCOVER: return "DEVICE_DISCOVER";
        case RAWR_STAGE_CAPABILITY_SOLVE: return "CAPABILITY_SOLVE";
        case RAWR_STAGE_GEOMETRY_PROBE: return "GEOMETRY_PROBE";
        case RAWR_STAGE_SHADER_VARIANTS: return "SHADER_VARIANTS";
        case RAWR_STAGE_KERNEL_CANDIDATES: return "KERNEL_CANDIDATES";
        case RAWR_STAGE_LEGALITY_FILTER: return "LEGALITY_FILTER";
        case RAWR_STAGE_PARITY_MEASURE: return "PARITY_MEASURE";
        case RAWR_STAGE_WINNER_SELECT: return "WINNER_SELECT";
        case RAWR_STAGE_PROMPT_TOKENIZE: return "PROMPT_TOKENIZE";
        case RAWR_STAGE_EMBED: return "EMBED";
        case RAWR_STAGE_PREFILL_LAYER: return "PREFILL_LAYER";
        case RAWR_STAGE_DECODE_LAYER: return "DECODE_LAYER";
        case RAWR_STAGE_ATTENTION: return "ATTENTION";
        case RAWR_STAGE_Q_PROJ: return "Q_PROJ";
        case RAWR_STAGE_K_PROJ: return "K_PROJ";
        case RAWR_STAGE_V_PROJ: return "V_PROJ";
        case RAWR_STAGE_QKV_PROJ: return "QKV_PROJ";
        case RAWR_STAGE_KVA: return "KVA";
        case RAWR_STAGE_O_PROJ: return "O_PROJ";
        case RAWR_STAGE_FFN_GATE: return "FFN_GATE";
        case RAWR_STAGE_FFN_UP: return "FFN_UP";
        case RAWR_STAGE_FFN_DOWN: return "FFN_DOWN";
        case RAWR_STAGE_RMSNORM: return "RMSNORM";
        case RAWR_STAGE_FINAL_NORM: return "FINAL_NORM";
        case RAWR_STAGE_LOGITS: return "LOGITS";
        case RAWR_STAGE_SAMPLE: return "SAMPLE";
        case RAWR_STAGE_DETOKENIZE: return "DETOKENIZE";
        case RAWR_STAGE_TOKEN_EMIT: return "TOKEN_EMIT";
        case RAWR_STAGE_STOP_CHECK: return "STOP_CHECK";
        case RAWR_STAGE_TEARDOWN: return "TEARDOWN";
        default: return "UNKNOWN";
    }
}
