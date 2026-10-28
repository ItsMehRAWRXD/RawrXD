/* Harness-only MagBuf stubs so batch_005.obj can link without Mag registry TU.
 * get_baseline does not call these; verify/get_status UNDEFs still need symbols. */
#include <stdint.h>

void mag_watchdog_region_peek(void** outRegion, uint32_t* outBytes) {
    if (outRegion) *outRegion = 0;
    if (outBytes) *outBytes = 0;
}

uint32_t mag_watchdog_crc32_region(void) {
    return 0;
}
