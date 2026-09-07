// minimal_result.hpp — sovereign-friendly ABI (no STL, no Ship, no expected)
#pragma once
#ifdef __cplusplus
extern "C" {
#endif

typedef struct CertResult {
    int success;       // 1 = ok, 0 = fail
    int error_code;
    char message[256];
    double duration_ms;
} CertResult;

static inline CertResult CertOk(const char* msg) {
    CertResult r;
    r.success = 1;
    r.error_code = 0;
    r.duration_ms = 0.0;
    r.message[0] = 0;
    if (msg) {
        size_t i = 0;
        for (; msg[i] && i + 1 < sizeof(r.message); ++i) r.message[i] = msg[i];
        r.message[i] = 0;
    }
    return r;
}

static inline CertResult CertFail(int code, const char* msg) {
    CertResult r = CertOk(msg);
    r.success = 0;
    r.error_code = code;
    return r;
}

#ifdef __cplusplus
}
#endif
