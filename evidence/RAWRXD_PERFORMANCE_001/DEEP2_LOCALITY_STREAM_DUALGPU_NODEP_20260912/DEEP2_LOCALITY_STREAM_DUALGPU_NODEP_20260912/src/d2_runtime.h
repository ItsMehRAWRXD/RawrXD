#ifndef D2_RUNTIME_H
#define D2_RUNTIME_H
#include "d2_plan.h"
#ifdef __cplusplus
extern "C" {
#endif
typedef struct D2DeviceIo {
    void *ctx;
    int (*load_exact)(void *ctx,uint32_t device,const D2ByteRange *range,uint64_t ticket);
    int (*evict_tensor)(void *ctx,uint32_t device,uint64_t tensor_id);
    int (*copy_tensor)(void *ctx,uint32_t src,uint32_t dst,uint64_t tensor_id,uint64_t bytes);
} D2DeviceIo;
typedef struct D2Runtime {
    D2Locality locality;
    D2Residency residency;
    D2StreamQueue stream;
    D2DeviceIo io;
} D2Runtime;
void d2_runtime_init(D2Runtime *r,const D2DeviceIo *io,uint64_t budget0,uint64_t budget1,uint64_t bw0,uint64_t bw1);
int d2_runtime_stage_plan(D2Runtime *r,const D2TokenPlan *plan);
int d2_runtime_pump_one(D2Runtime *r,uint64_t token);
#ifdef __cplusplus
}
#endif
#endif
