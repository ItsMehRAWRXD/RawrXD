#include "cpu_inference_engine.h"

#include <iostream>
#include <string>

int main(int argc, char** argv)
{
    std::cout << "[smoke] RawrXD inference harness start\n";

    (void)argc;
    (void)argv;

    // Verify the CPU inference core is reachable and constructible.
    auto sharedEngine = RawrXD::CPUInferenceEngine::GetSharedInstance();
    if (!sharedEngine)
    {
        std::cerr << "[smoke] CPUInferenceEngine shared instance unavailable\n";
        return 2;
    }
    std::cout << "[smoke] Engine: " << sharedEngine->GetEngineName() << "\n";

    std::cout << "[smoke] CPUInferenceEngine constructor/link smoke passed\n";
    std::cout << "[smoke] model-load/inference path is validated by orchestrator/runtime tests\n";

    std::cout << "[smoke] success\n";
    return 0;
}
