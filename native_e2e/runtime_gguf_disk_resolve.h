#pragma once
#include "rawr_native_e2e_abi.h"

#ifdef __cplusplus
extern "C" {
#endif

uint32_t RawrNative_TryRegisterRuntimeGgufFromDisk(
    const char* model_name, RawrNativeProfileInfo* out_info);

uint32_t RawrNative_RegisterRuntimeGgufPath(
    const char* model_name, const char* gguf_path);

uint32_t RawrNative_RegisterRuntimeGgufPathEx(
    const char* model_name, const char* gguf_path,
    RawrNativeProfileInfo* out_info);

#ifdef __cplusplus
}
#endif
