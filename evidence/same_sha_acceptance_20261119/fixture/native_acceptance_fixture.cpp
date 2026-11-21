// Deterministic process-outcome fixture for native acceptance tests.
// Modes: silent (exit 0, no stderr) | marker (exit 0, [BRIDGE_GEN] on stderr)
//        failure (exit 7) | default (exit 2)
#include <cstdio>
#include <cstring>

int main(int argc, char** argv)
{
    if (argc < 2) return 2;
    if (std::strcmp(argv[1], "silent") == 0) return 0;
    if (std::strcmp(argv[1], "marker") == 0) {
        std::fputs("[BRIDGE_GEN] gpu_dispatches=12\n", stderr);
        std::fflush(stderr);
        return 0;
    }
    if (std::strcmp(argv[1], "failure") == 0) return 7;
    return 2;
}