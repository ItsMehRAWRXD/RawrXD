// Compile check: execution owners carry runtime device-loss state (OWN-09).
#include "VwaGpuDma_Session.hpp"

int main() {
    Deep2::GpuDmaSession s;
    s.deviceLost = true;
    return (s.deviceLost && s.dev == VK_NULL_HANDLE) ? 0 : 1;
}