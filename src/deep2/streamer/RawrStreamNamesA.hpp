#pragma once
#include "RawrStreamState.hpp"
#include "RawrStreamStage.hpp"
#include "RawrStreamEvent.hpp"

static inline const char* RawrStreamStateName(RawrStreamState v) {
    switch (v) {
        case RAWR_STREAM_COLD: return "COLD";
        case RAWR_STREAM_BOOT: return "BOOT";
        case RAWR_STREAM_MODEL_RESOLVE: return "MODEL_RESOLVE";
        case RAWR_STREAM_MODEL_OPEN: return "MODEL_OPEN";
        case RAWR_STREAM_MODEL_INDEX: return "MODEL_INDEX";
        case RAWR_STREAM_MODEL_FACTS: return "MODEL_FACTS";
        case RAWR_STREAM_TOKENIZER_OPEN: return "TOKENIZER_OPEN";
        case RAWR_STREAM_EXEC_CREATE: return "EXEC_CREATE";
        case RAWR_STREAM_CAP_DISCOVER: return "CAP_DISCOVER";
        case RAWR_STREAM_SPACE_SNAPSHOT: return "SPACE_SNAPSHOT";
        case RAWR_STREAM_PLAN: return "PLAN";
        case RAWR_STREAM_PREFILL: return "PREFILL";
        case RAWR_STREAM_DECODE: return "DECODE";
        case RAWR_STREAM_EMIT: return "EMIT";
        case RAWR_STREAM_COMPLETE: return "COMPLETE";
        case RAWR_STREAM_BLOCKED: return "BLOCKED";
        case RAWR_STREAM_FAIL: return "FAIL";
        default: return "UNKNOWN";
    }
}

static inline const char* RawrStreamStatusName(RawrStreamStatus v) {
    switch (v) {
        case RAWR_STATUS_UNKNOWN: return "UNKNOWN";
        case RAWR_STATUS_PASS: return "PASS";
        case RAWR_STATUS_OPEN: return "OPEN";
        case RAWR_STATUS_BLOCKED: return "BLOCKED";
        case RAWR_STATUS_FAIL: return "FAIL";
        case RAWR_STATUS_SKIP: return "SKIP";
        case RAWR_STATUS_RETRY: return "RETRY";
        case RAWR_STATUS_RECOVERED: return "RECOVERED";
        default: return "UNKNOWN";
    }
}

static inline const char* RawrTokenStateName(RawrTokenState v) {
    switch (v) {
        case RAWR_TOKEN_NONE: return "NONE";
        case RAWR_TOKEN_PROMPT: return "PROMPT";
        case RAWR_TOKEN_PREFILL: return "PREFILL";
        case RAWR_TOKEN_DECODE: return "DECODE";
        case RAWR_TOKEN_SAMPLE: return "SAMPLE";
        case RAWR_TOKEN_EMIT: return "EMIT";
        case RAWR_TOKEN_STOP: return "STOP";
        default: return "UNKNOWN";
    }
}
