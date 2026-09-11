#pragma once
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif

#define RN_ENGINE_MODE_SINGLE      0x0001u
#define RN_ENGINE_MODE_SWARM       0x0002u
#define RN_ENGINE_MODE_DUALENGINE  0x0004u
#define RN_ENGINE_MODE_TENSORHOP   0x0008u
#define RN_ENGINE_MODE_SAFEDECODE  0x0010u
#define RN_ENGINE_MODE_FLASHATTN   0x0020u
#define RN_ENGINE_MODE_5DRIVE      0x0040u

#define RN_HOP_AUTO    0u
#define RN_HOP_EVEN    1u
#define RN_HOP_FRONT   2u
#define RN_HOP_BACK    3u
#define RN_HOP_CUSTOM  4u

#define RN_POLICY_SAFE_ELIGIBLE      0x00000001u
#define RN_POLICY_SAFE_PREPARED      0x00000002u
#define RN_POLICY_HOP_ELIGIBLE       0x00000004u
#define RN_POLICY_HOP_PREPARED       0x00000008u
#define RN_POLICY_HOP_NEEDS_ENGINE   0x00000010u
#define RN_POLICY_CLAMPED            0x00000020u

#define RN_HTTP_GET   0x01u
#define RN_HTTP_POST  0x02u
#define RN_HTTP_ANY   (RN_HTTP_GET|RN_HTTP_POST)

typedef struct RawrNativeProfileInfo {
    uint32_t profile_id;
    uint32_t engine_mode;
    uint32_t num_layers;
    uint32_t context_default;
    uint32_t context_max;
    uint32_t max_tokens;
    uint32_t tier;
    uint32_t quant_type;
    uint32_t ram_mb;
    uint32_t vram_mb;
} RawrNativeProfileInfo;

typedef struct RawrNativePolicyRequest {
    uint32_t context;
    uint32_t max_tokens;
    uint32_t temperature_milli;
    uint32_t top_p_milli;
    uint32_t top_k;
    uint32_t stream;

    uint32_t safe_enabled;
    uint32_t safe_context;
    uint32_t safe_max_tokens;
    uint32_t safe_temperature_milli;
    uint32_t safe_top_p_milli;
    uint32_t safe_top_k;

    uint32_t hop_enabled;
    uint32_t hop_strategy;
    uint32_t hop_skip_permille;
    uint32_t hop_keep_first;
    uint32_t hop_keep_last;
    uint32_t reserved0;

    uint64_t hop_custom_mask[4];
} RawrNativePolicyRequest;

typedef struct RawrNativePolicy {
    uint32_t context;
    uint32_t max_tokens;
    uint32_t temperature_milli;
    uint32_t top_p_milli;
    uint32_t top_k;
    uint32_t stream;

    uint32_t flags;
    uint32_t hop_strategy;
    uint32_t hop_skip_count;
    uint32_t reserved0;

    uint64_t hop_mask[4];
} RawrNativePolicy;

typedef struct RawrNativeReceipt {
    uint64_t request_id;
    uint64_t qpc_begin;
    uint64_t qpc_engine_enter;
    uint64_t qpc_first_token;
    uint64_t qpc_end;
    uint32_t profile_id;
    uint32_t requested_flags;
    uint32_t prepared_flags;
    uint32_t engine_applied_flags;
    uint32_t backend_id;
    int32_t  engine_status;
    uint64_t generated_tokens;
} RawrNativeReceipt;

uint64_t __cdecl RawrNative_ModelBridgeCapabilities(void);
uint32_t __cdecl RawrNative_ModelBridgeResolveProfile(
    const char* model_name, RawrNativeProfileInfo* out_info);

/* Exact runtime GGUF metadata can override/fill static ModelBridge profiles.
 * RegisterRuntimeModelSrc source examples: model_metadata | seed_compat */
uint32_t RawrNative_RegisterRuntimeModel(
    const char* model_name, const RawrNativeProfileInfo* info);
uint32_t RawrNative_RegisterRuntimeModelSrc(
    const char* model_name, const RawrNativeProfileInfo* info,
    const char* source);
uint32_t RawrNative_UnregisterRuntimeModel(const char* model_name);

uint32_t __cdecl RawrNative_NormalizePolicy(
    const RawrNativeProfileInfo* profile,
    const RawrNativePolicyRequest* request,
    RawrNativePolicy* out_policy);

uint64_t __cdecl RawrNative_ReceiptBegin(
    uint32_t profile_id, uint32_t requested_flags, uint32_t prepared_flags);
void __cdecl RawrNative_ReceiptEngineEnter(
    uint64_t request_id, uint32_t backend_id, uint32_t engine_applied_flags);
void __cdecl RawrNative_ReceiptFirstToken(uint64_t request_id);
void __cdecl RawrNative_ReceiptComplete(
    uint64_t request_id, uint64_t generated_tokens, int32_t engine_status);
uint32_t __cdecl RawrNative_ReceiptGet(
    uint64_t request_id, RawrNativeReceipt* out_receipt);
uint64_t __cdecl RawrNative_ReceiptLatestId(void);

void RawrNative_RegisterRouteAttachment(const char* path, uint32_t method_mask);
int RawrNative_HandleHttp(
    const char* method, const char* path, const char* body,
    char* out_json, uint32_t out_capacity, uint32_t* out_http_status);

#ifdef __cplusplus
}
#endif
