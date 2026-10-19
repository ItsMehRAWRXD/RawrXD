#ifndef RAWRXD_DS671_TENSOR_IO_H
#define RAWRXD_DS671_TENSOR_IO_H
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
int ds671_win_read_at(
    const char *path, uint64_t offset, void *dst, uint64_t nbytes);
void *ds671_win_alloc32(uint64_t bytes);
void ds671_win_free32(void *p);
#ifdef __cplusplus
}
#endif
#endif
