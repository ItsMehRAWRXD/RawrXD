// =============================================================================
// engine_build_stamp.cpp — Deep2 engine build fingerprint (P0 provenance).
// =============================================================================
// A unique TU whose build time is embedded so the server can print the exact
// engine object it linked (stale-object detection).
// =============================================================================
#include <cstdio>

extern "C" const char* Deep2_EngineBuildStamp() {
    return "deep2-engine " __DATE__ " " __TIME__;
}

extern "C" const char* Deep2_EngineBuildStampPrint() {
    static const char* s = Deep2_EngineBuildStamp();
    return s;
}