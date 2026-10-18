#pragma once
#include "Deep2NoDepSha256.hpp"
#include <string>
#include <cstdint>

namespace Deep2 {

struct B73StoredReceipt {
    bool pass = false;
    const char* failure = "UNSET";
    std::string receiptPath;
    std::string hashPath;
    std::string sha256;
};

class B73EvidenceStore {
public:
    static B73StoredReceipt writeAtomic(const std::string& directory,
                                        const std::string& stem,
                                        const std::string& canonicalText) noexcept;
    static bool readAll(const std::string& path,
                        std::string& out) noexcept;
};

} // namespace Deep2
