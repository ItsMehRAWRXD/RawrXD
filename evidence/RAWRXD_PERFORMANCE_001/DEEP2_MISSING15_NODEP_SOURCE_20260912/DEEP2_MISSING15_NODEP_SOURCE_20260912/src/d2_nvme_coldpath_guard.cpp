#include "d2_nodep.h"

extern "C" int d2_nvme_critical_path_guard(uint64_t reads_per_token) {
    return reads_per_token == 0 ? 1 : 0;
}
