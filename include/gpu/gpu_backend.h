
#ifndef GPU_BACKEND_H
#define GPU_BACKEND_H

#include <string>
#include <map>

class GpuBackend
{
public:
    enum Backend {
        CPU,
        Vulkan,
        CUDA
    };

    static bool initialize(Backend backend = Vulkan);
    static Backend currentBackend();
    static bool isBackendAvailable(Backend backend);
    static std::string backendName(Backend backend);
    static bool initializeWithFallback();

private:
    static Backend s_currentBackend;
    static bool s_initialized;
    static bool initializeVulkan();
    static bool initializeCuda();
    static bool initializeCpu();
};

#endif // GPU_BACKEND_H

