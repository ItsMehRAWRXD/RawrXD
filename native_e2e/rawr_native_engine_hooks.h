#pragma once
#include "rawr_native_e2e_abi.h"

/* Call at the REAL Deep2 execution boundary. */
#define RAWR_NATIVE_ENGINE_ENTER(id,backend,flags) \
    RawrNative_ReceiptEngineEnter((id),(backend),(flags))
#define RAWR_NATIVE_FIRST_TOKEN(id) \
    RawrNative_ReceiptFirstToken((id))
#define RAWR_NATIVE_COMPLETE(id,tokens,status) \
    RawrNative_ReceiptComplete((id),(tokens),(status))
