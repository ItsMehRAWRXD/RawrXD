#include "hexmag/HexMagReapBridge.hpp"

#include <iostream>

int main(int argc, char** argv) {
    if (argc < 6 || argc > 7) {
        std::cerr << "Usage: hexmag-reap-live <model.gguf|dir> <parameters/experts> "
                     "<https-url> <query> <evidence-bytes> [receipt]\n";
        return 2;
    }
    RawrXD::HexMag::LiveRequest request;
    request.modelPath = argv[1];
    request.reapTarget = argv[2];
    request.url = argv[3];
    request.query = argv[4];
    try {
        request.evidenceBudgetBytes = std::stoull(argv[5]);
    } catch (...) {
        std::cerr << "Invalid evidence byte budget\n";
        return 2;
    }
    if (argc == 7) request.receiptPath = argv[6];
    const auto result = RawrXD::HexMag::RunLive(request);
    std::cout << result.receipt;
    return result.exitCode;
}
