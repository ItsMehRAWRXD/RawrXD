// tokenizer_rebuild_gate.cpp — REBUILD gate after TOKENIZER-PARITY-002c
#include "GGUFTokenizerLoad.hpp"

#include <cstdio>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")
#endif

static constexpr const char* kFrozenSha =
    "FBCBBE536C2A9D6ACA83756EFA37BF85FAE05634F34AD70373CD30C723EC0EAA";
static constexpr size_t kExpectedCount = 898;

static std::string readAll(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    std::ostringstream ss;
    ss << f.rdbuf();
    return ss.str();
}

static std::string toHexUpper(const unsigned char* dig, size_t n) {
    static const char* hex = "0123456789ABCDEF";
    std::string out(n * 2, '\0');
    for (size_t i = 0; i < n; ++i) {
        out[i * 2] = hex[dig[i] >> 4];
        out[i * 2 + 1] = hex[dig[i] & 0xF];
    }
    return out;
}

static std::string sha256Bytes(const std::string& data) {
#ifdef _WIN32
    BCRYPT_ALG_HANDLE alg = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    DWORD objLen = 0, dataLen = 0, hashLen = 0;
    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0) != 0)
        return {};
    BCryptGetProperty(alg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&objLen, sizeof(objLen), &dataLen, 0);
    BCryptGetProperty(alg, BCRYPT_HASH_LENGTH, (PUCHAR)&hashLen, sizeof(hashLen), &dataLen, 0);
    std::vector<UCHAR> obj(objLen), dig(hashLen);
    if (BCryptCreateHash(alg, &hash, obj.data(), objLen, nullptr, 0, 0) != 0) {
        BCryptCloseAlgorithmProvider(alg, 0);
        return {};
    }
    BCryptHashData(hash, (PUCHAR)data.data(), (ULONG)data.size(), 0);
    BCryptFinishHash(hash, dig.data(), hashLen, 0);
    BCryptDestroyHash(hash);
    BCryptCloseAlgorithmProvider(alg, 0);
    return toHexUpper(dig.data(), dig.size());
#else
    (void)data;
    return {};
#endif
}

int main(int argc, char** argv) {
    const char* model =
        argc > 1 ? argv[1]
                 : "F:\\~dev\\rawrxd\\models\\tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf";
    const char* promptPath =
        argc > 2 ? argv[2]
                 : "F:\\~dev\\rawrxd\\evidence\\AGENT_E2E_002b\\TOKENIZER_PARITY_002c\\rendered_prompt.FROZEN.bin";
    const char* outDir =
        argc > 3 ? argv[3]
                 : "F:\\~dev\\rawrxd\\evidence\\AGENT_E2E_002b\\TOKENIZER_REBUILD_GATE";

    const std::string prompt = readAll(promptPath);
    const std::string sha = sha256Bytes(prompt);

    auto bundle = Deep2::LoadTokenizerFromGGUF(model);
    if (!bundle.ok) {
        std::fprintf(stderr, "[FAIL] LoadTokenizerFromGGUF: %s\n", bundle.error);
        return 2;
    }
    Deep2::BPETokenizer tok;
    if (!Deep2::ApplyTokenizerBundle(tok, bundle)) {
        std::fprintf(stderr, "[FAIL] ApplyTokenizerBundle\n");
        return 2;
    }

    const std::vector<int> ids = tok.Encode(prompt);
    bool has35 = false;
    for (int id : ids) {
        if (id == 35) {
            has35 = true;
            break;
        }
    }

    const bool shaOk = (sha == kFrozenSha);
    const bool countOk = (ids.size() == kExpectedCount);
    const bool pass = shaOk && countOk && !has35;

#ifdef _WIN32
    CreateDirectoryA(outDir, nullptr);
#endif

    {
        std::ofstream f(std::string(outDir) + "\\rebuilt_ids.txt");
        for (size_t i = 0; i < ids.size(); ++i) {
            if (i) f << ',';
            f << ids[i];
        }
        f << '\n';
    }
    {
        std::ofstream f(std::string(outDir) + "\\VERDICT.txt");
        f << "TOKENIZER_REBUILD_GATE\n\n";
        f << "FROZEN_PROMPT_SHA=" << sha << "\n";
        f << "FROZEN_PROMPT_SHA_EXPECTED=" << kFrozenSha << "\n";
        f << "FROZEN_PROMPT_SHA_MATCH=" << (shaOk ? "true" : "false") << "\n";
        f << "prompt_bytes=" << prompt.size() << "\n";
        f << "REBUILT_AGENT_TOKEN_COUNT=" << ids.size() << "\n";
        f << "TOKEN_35_PRESENT=" << (has35 ? "true" : "false") << "\n";
        f << "first_id=" << (ids.empty() ? -1 : ids.front()) << "\n";
        f << "last_id=" << (ids.empty() ? -1 : ids.back()) << "\n";
        f << "encode_authority=BPETokenizer::Encode -> RawrXD::Spm::encode\n\n";
        f << "VERDICT=" << (pass ? "PASS" : "FAIL") << "\n";
        if (pass) {
            f << "REBUILT_BINARY_AUTHORIZED_FOR_FORWARD_EVIDENCE=true\n";
        }
    }

    std::printf("TOKENIZER_REBUILD_GATE\n");
    std::printf("FROZEN_PROMPT_SHA=%s match=%d\n", sha.c_str(), (int)shaOk);
    std::printf("REBUILT_AGENT_TOKEN_COUNT=%zu\n", ids.size());
    std::printf("TOKEN_35_PRESENT=%s\n", has35 ? "true" : "false");
    std::printf("VERDICT=%s\n", pass ? "PASS" : "FAIL");
    return pass ? 0 : 1;
}
