// ============================================================================
// RawrXDHost.exe — Native Host Control Plane Entry Point
// B017: Thin control plane, zero inference duplication
// ============================================================================
#include "rawrxd_host.hpp"
#include "rawrxd_pipe_server.hpp"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <windows.h>

static void PrintUsage(const char* prog)
{
    std::printf("Usage: %s [options]\n", prog);
    std::printf("Options:\n");
    std::printf("  --pipe NAME    Named pipe path (default: \\\\ .\\pipe\\RawrXD)\n");
    std::printf("  --residency MB Weight residency pool max MB (default: 512)\n");
    std::printf("  --gpu INDEX    GPU device index (default: 0)\n");
    std::printf("  --help         Show this message\n");
}

int main(int argc, char** argv)
{
    const char* pipe_name = nullptr;
    uint64_t residency_mb = 512;
    uint32_t gpu_index = 0;

    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "--help") == 0 || std::strcmp(argv[i], "-h") == 0) {
            PrintUsage(argv[0]);
            return 0;
        }
        if (std::strcmp(argv[i], "--pipe") == 0 && i + 1 < argc) {
            pipe_name = argv[++i];
        }
        else if (std::strcmp(argv[i], "--residency") == 0 && i + 1 < argc) {
            residency_mb = static_cast<uint64_t>(std::atoll(argv[++i]));
        }
        else if (std::strcmp(argv[i], "--gpu") == 0 && i + 1 < argc) {
            gpu_index = static_cast<uint32_t>(std::atoi(argv[++i]));
        }
    }

    std::printf("╔══════════════════════════════════════════════════════════════╗\n");
    std::printf("║  RawrXD Native Host Control Plane                            ║\n");
    std::printf("║  B017: IPC + C ABI + lifecycle + isolation                   ║\n");
    std::printf("╚══════════════════════════════════════════════════════════════╝\n");
    std::printf("  Pipe:      %s\n", pipe_name ? pipe_name : "\\\\.\\pipe\\RawrXD");
    std::printf("  Residency: %llu MB\n", static_cast<unsigned long long>(residency_mb));
    std::printf("  GPU:       %u\n", gpu_index);
    std::printf("\n");

    // Run the pipe server (blocks until shutdown)
    int rc = rawrxd_pipe_server_run(pipe_name);

    if (rc != RAWRXD_OK) {
        std::fprintf(stderr, "[Host] Pipe server exited with error: %d\n", rc);
        return 1;
    }

    std::printf("[Host] Clean shutdown.\n");
    return 0;
}
