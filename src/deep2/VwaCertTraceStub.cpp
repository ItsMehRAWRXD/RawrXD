// VwaCertTraceStub.cpp — no-op ResidencyTrace for narrow consumer certs
#include "ResidencyTrace.hpp"

extern "C" {

int TraceInit(const char*) { return 1; }
void TraceShutdown(void) {}
ResidencyEvent* TraceBegin(uint32_t, uint32_t, uint32_t, uint64_t, uint32_t, uint32_t) {
    return nullptr;
}
void TraceSetDestination(ResidencyEvent*, uint32_t, uint64_t, uint64_t, uint64_t,
                         uint32_t, uint32_t) {}
void TraceComplete(ResidencyEvent*, uint64_t, uint64_t, int) {}
void TraceFlush(void) {}

}
