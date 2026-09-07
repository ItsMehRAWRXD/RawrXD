// Mech end: stream telemetry + ResourceReversal
#include "Deep2LivePath.hpp"
#include "Deep2LivePath_Internal.hpp"
#include "StreamEngine.hpp"
#include "time_reversal/ResourceReversal.hpp"
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

namespace Deep2 {

StreamEngine& LivePath_MechStream();
bool& LivePath_MechStreamReady();

void LivePath_MechEndImpl() {
    if (!LivePath_MechOn(LP_MECH_REVERSAL) && !LivePath_MechOn(LP_MECH_STREAM))
        return;
    auto& c = LivePath_Ctr();
    if (LivePath_MechOn(LP_MECH_STREAM) && LivePath_MechStreamReady() &&
        c.streamBytesRead == 0 && c.streamReadOps == 0) {
        auto t = LivePath_MechStream().GetTelemetry();
        c.streamBytesRead = t.bytesSlingshot;
        c.streamBytesToGpu = t.bytesDecompressed;
        c.streamBytesReconstructed = t.bytesDecompressed;
        c.streamReadOps = t.totalLayers;
        c.streamCacheHits = t.cacheHits;
        c.streamCacheMisses = t.cacheMisses;
    }
    TimeReversal::ResourceSnapshot s;
#ifdef _WIN32
    MEMORYSTATUSEX mx{};
    mx.dwLength = sizeof(mx);
    if (LivePath_MechOn(LP_MECH_REVERSAL) && GlobalMemoryStatusEx(&mx)) {
        s.ramTotalMiB = (double)mx.ullTotalPhys / (1024.0 * 1024.0);
        s.ramUsedMiB = (double)(mx.ullTotalPhys - mx.ullAvailPhys) / (1024.0 * 1024.0);
    }
#endif
    if (LivePath_MechOn(LP_MECH_REVERSAL))
        c.reversalUsPerToken =
            (float)TimeReversal::DeriveResourceOpportunity(s).estimatedRecoverableUsPerToken;
}

} // namespace Deep2
