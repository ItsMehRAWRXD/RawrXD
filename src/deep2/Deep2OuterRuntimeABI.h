/* Deep2OuterRuntimeABI.h — C ABI for outer host + engine vtable */
#pragma once
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif

enum {
    OUT_KIND_K2 = 1,
    OUT_KIND_DEEPSEEK = 2,
    OUT_EXPECT_K2 = 13,
    OUT_EXPECT_DS = 11,
    OUT_F_PATH = 1,
    OUT_F_DIR = 2,
    OUT_F_COMPLETE = 4,
    OUT_F_NO_DUP = 8,
    OUT_F_NO_MISS = 16,
    OUT_F_HDR_OK = 32,
    OUT_F_ALL = 63,
    OUT_E_OPEN_ENTERED = 1,
    OUT_E_OPEN_HANDLE = 2,
    OUT_E_GEN_ENTERED = 4,
    OUT_E_GEN_OK = 8,
    OUT_E_CLOSE_ENTERED = 16,
    OUT_E_ALL = 31
};

typedef struct Deep2OuterEngineApi {
    uint32_t (*open)(const char* dir, void** handle);
    uint32_t (*generate)(void* handle, const char* prompt, uint32_t nTok);
    void (*close)(void* handle);
} Deep2OuterEngineApi;

typedef struct Deep2OuterHostRec {
    uint32_t flags;
    uint32_t shards;
    uint32_t expected;
    uint32_t engFlags;
    uint64_t qpcTicks;
    uint64_t qpcT0;
    uint64_t qpcOpen;
    uint64_t qpcFirst;
    uint64_t qpcEnd;
} Deep2OuterHostRec;

uint32_t Deep2Outer_GetEnvPath(uint32_t kind, char* dst, uint32_t dstBytes);
uint32_t Deep2Outer_ParseSplitName(const char* name, uint32_t* index, uint32_t* total);
uint32_t Deep2Outer_CheckGgufHeader(const char* path);
uint32_t Deep2Outer_ScanDirectory(const char* dir, uint32_t expected, void* scanRec);
uint32_t Deep2Outer_WriteEvidence(const Deep2OuterHostRec* rec);
uint32_t Deep2Outer_RunProbe(uint32_t kind, const Deep2OuterEngineApi* api,
                             Deep2OuterHostRec* rec);

#ifdef __cplusplus
}
#endif
