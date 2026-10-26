#include "IdeAuthBoundary.hpp"
#include <windows.h>
#include <bcrypt.h>
#include <cstdlib>
#include <fstream>
#include <sstream>
#include <string>
#pragma comment(lib, "bcrypt.lib")

namespace RawrXD::IdeAuth {
namespace {
bool Sha256File(const std::string& path, std::string& hexOut) {
    BCRYPT_ALG_HANDLE alg = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0) != 0)
        return false;
    DWORD objLen = 0, cb = 0;
    BCryptGetProperty(alg, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&objLen),
                      sizeof(objLen), &cb, 0);
    std::string obj(objLen, '\0');
    bool ok = BCryptCreateHash(alg, &hash, reinterpret_cast<PUCHAR>(obj.data()),
                               objLen, nullptr, 0, 0) == 0;
    std::ifstream in(path, std::ios::binary);
    char buf[8192];
    while (ok && in) {
        in.read(buf, sizeof(buf));
        if (in.gcount() > 0)
            ok = BCryptHashData(hash, reinterpret_cast<PUCHAR>(buf),
                                static_cast<ULONG>(in.gcount()), 0) == 0;
    }
    unsigned char dig[32] = {};
    ok = ok && BCryptFinishHash(hash, dig, sizeof(dig), 0) == 0;
    if (hash) BCryptDestroyHash(hash);
    if (alg) BCryptCloseAlgorithmProvider(alg, 0);
    if (!ok) return false;
    static const char* hexd = "0123456789abcdef";
    hexOut.clear();
    for (unsigned char b : dig) {
        hexOut.push_back(hexd[b >> 4]);
        hexOut.push_back(hexd[b & 0xF]);
    }
    return true;
}
}

bool ExtensionHashTrusted(const std::string& packagePath, std::string& error) {
    std::string digest;
    if (!Sha256File(packagePath, digest)) {
        error = "extension hash failed";
        return false;
    }
    const char* env = std::getenv("RAWRXD_EXTENSION_TRUST");
    std::string trustPath = env && env[0] ? env : std::string("extension_trust.txt");
    std::ifstream list(trustPath);
    if (!list) {
        error = "extension trust list missing";
        return false;
    }
    std::string line;
    while (std::getline(list, line)) {
        while (!line.empty() && (line.back() == '\r' || line.back() == ' ')) line.pop_back();
        for (char& c : line) c = static_cast<char>(tolower(static_cast<unsigned char>(c)));
        if (line == digest) return true;
    }
    error = "extension sha256 not in trust list";
    return false;
}
}
