#ifndef D2_LINK15_ADAPTER_H
#define D2_LINK15_ADAPTER_H
#include "d2_link15.h"
#ifdef __cplusplus
extern "C" {
#endif

typedef int (*D2OpaqueCall)(void *opaque, D2LinkId id, D2LinkEvidence *out);
typedef struct D2AdapterThunk {
    D2OpaqueCall call;
    void *opaque;
    D2LinkId id;
} D2AdapterThunk;

int d2_link15_opaque_adapter(void *user, D2LinkContext *ctx, D2LinkEvidence *out);

#ifdef __cplusplus
}
#endif
#endif
