#pragma once
/* Product-path invariants — apply/elastic remain compile-closed. ≤99. */

#ifndef RAWRXD_APPLY_HOST_DECODE
#define RAWRXD_APPLY_HOST_DECODE 0
#endif
#ifndef RAWRXD_ENABLE_ELASTIC_RESIDENCY
#define RAWRXD_ENABLE_ELASTIC_RESIDENCY 0
#endif

static_assert(RAWRXD_APPLY_HOST_DECODE == 0,
              "RAWRXD_APPLY_HOST_DECODE must stay 0 (R28 apply held)");
static_assert(RAWRXD_ENABLE_ELASTIC_RESIDENCY == 0,
              "RAWRXD_ENABLE_ELASTIC_RESIDENCY must stay 0");
