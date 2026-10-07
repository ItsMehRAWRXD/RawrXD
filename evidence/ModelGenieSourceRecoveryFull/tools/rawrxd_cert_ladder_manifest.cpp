// rawrxd_cert_ladder_manifest — print ordered next todos from evidence GATEs
#include "RuntimeManifest.hpp"
#include <cstdio>
#include <fstream>
#include <string>

#ifdef _WIN32
#include <direct.h>
#else
#include <sys/stat.h>
#endif

int main(int argc, char** argv) {
    const char* evidence = argc > 1 ? argv[1]
        : R"(F:\~dev\rawrxd\evidence\DEEP2_PARITY_PROBE_001)";
    const char* outJson = argc > 2 ? argv[2]
        : R"(g:\rawrxd\generated\CertLadderManifest.json)";
    const char* outBoard = argc > 3 ? argv[3]
        : R"(g:\rawrxd\generated\CertLadderTodos.txt)";

    auto snap = RawrXD::Self::buildCertLadderManifest(evidence);
    const std::string json = RawrXD::Self::snapshotToJson(snap);
    const std::string board = RawrXD::Self::snapshotToTodoBoard(snap);

    std::printf("%s\n", board.c_str());

#ifdef _WIN32
    _mkdir("g:\\rawrxd\\generated");
#else
    mkdir("g:/rawrxd/generated", 0755);
#endif
    {
        std::ofstream o(outJson, std::ios::binary);
        if (o) o << json;
    }
    {
        std::ofstream o(outBoard, std::ios::binary);
        if (o) o << board;
    }
    std::printf("wrote %s\nwrote %s\nDO_NOW=%s\n", outJson, outBoard,
                snap.firstOpen.empty() ? "(none)" : snap.firstOpen.c_str());
    return 0;
}
