#ifndef BS_LOGSCAN_H
#define BS_LOGSCAN_H
#include "bs_common.h"
int bs_scan_cert_log(const char *path, BsState *s);
int bs_scan_smoke_file(const char *path, const char *key);
#endif
