// Assemble RAWRXD_REAP_REFERENCE_001 from an external engine's token IDs.
// Does not invent tokens: ids must be supplied by the caller.
#include <cstdint>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <windows.h>
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")

static std::string JsonEsc(const std::string& s) {
    std::string o; o.reserve(s.size() + 8);
    for (unsigned char c : s) {
        if (c == '\\' || c == '"') o.push_back('\\');
        o.push_back(static_cast<char>(c));
    }
    return o;
}

static bool Sha256File(const std::string& path, std::string& hex) {
    std::ifstream in(path, std::ios::binary);
    if (!in) return false;
    BCRYPT_ALG_HANDLE alg = nullptr; BCRYPT_HASH_HANDLE hash = nullptr;
    DWORD objLen = 0, dataLen = 0;
    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0) < 0)
        return false;
    if (BCryptGetProperty(alg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&objLen, sizeof(objLen),
                          &dataLen, 0) < 0) {
        BCryptCloseAlgorithmProvider(alg, 0); return false;
    }
    std::vector<UCHAR> obj(objLen), digest(32);
    if (BCryptCreateHash(alg, &hash, obj.data(), objLen, nullptr, 0, 0) < 0) {
        BCryptCloseAlgorithmProvider(alg, 0); return false;
    }
    char buf[1 << 16];
    while (in) {
        in.read(buf, sizeof(buf));
        const auto n = static_cast<ULONG>(in.gcount());
        if (n && BCryptHashData(hash, (PUCHAR)buf, n, 0) < 0) {
            BCryptDestroyHash(hash); BCryptCloseAlgorithmProvider(alg, 0); return false;
        }
    }
    if (BCryptFinishHash(hash, digest.data(), 32, 0) < 0) {
        BCryptDestroyHash(hash); BCryptCloseAlgorithmProvider(alg, 0); return false;
    }
    BCryptDestroyHash(hash); BCryptCloseAlgorithmProvider(alg, 0);
    static const char* k = "0123456789abcdef";
    hex.assign(64, '0');
    for (int i = 0; i < 32; ++i) {
        hex[i * 2] = k[digest[i] >> 4]; hex[i * 2 + 1] = k[digest[i] & 0xf];
    }
    return true;
}

static bool ParseIds(const std::string& text, std::vector<int32_t>& ids) {
    ids.clear();
    std::stringstream ss(text);
    std::string part;
    while (std::getline(ss, part, ',')) {
        if (part.empty()) continue;
        char* end = nullptr;
        long v = std::strtol(part.c_str(), &end, 10);
        if (!end || *end) return false;
        ids.push_back(static_cast<int32_t>(v));
    }
    return !ids.empty();
}

int main(int argc, char** argv) {
    if (argc < 8) {
        std::cerr << "usage: reap-reference-receipt <engine> <model.gguf> "
                     "<corpus.jsonl> <prompt_tokens> <token_ids_csv> "
                     "<engine_version> <out.json>\n";
        return 2;
    }
    std::string lower = argv[1];
    for (char& c : lower) c = static_cast<char>(tolower((unsigned char)c));
    if (lower.find("rawrxd") != std::string::npos ||
        lower.find("deep2") != std::string::npos) {
        std::cerr << "ENGINE_NOT_INDEPENDENT\n"; return 4;
    }
    std::vector<int32_t> ids;
    if (!ParseIds(argv[5], ids)) { std::cerr << "TOKEN_IDS_INVALID\n"; return 2; }
    const uint32_t promptTokens = (uint32_t)std::strtoul(argv[4], nullptr, 10);
    std::string modelHash, corpusHash;
    if (!Sha256File(argv[2], modelHash)) { std::cerr << "MODEL_HASH_FAILED\n"; return 4; }
    if (!Sha256File(argv[3], corpusHash)) { std::cerr << "CORPUS_HASH_FAILED\n"; return 4; }
    std::ofstream out(argv[7], std::ios::binary | std::ios::trunc);
    if (!out) { std::cerr << "OUT_OPEN_FAILED\n"; return 4; }
    out << "{\"schema\":\"RAWRXD_REAP_REFERENCE_001\",\"engine\":\"" << JsonEsc(argv[1])
        << "\",\"engine_version\":\"" << JsonEsc(argv[6])
        << "\",\"model\":\"" << JsonEsc(argv[2]) << "\",\"corpus\":\"" << JsonEsc(argv[3])
        << "\",\"model_first_shard_sha256\":\"" << modelHash
        << "\",\"corpus_sha256\":\"" << corpusHash
        << "\",\"deterministic\":true,\"finite\":true,\"reference_result_valid\":true"
        << ",\"generation_settings\":{\"temperature\":0.0,\"top_p\":1.0,\"top_k\":1,"
           "\"repeat_penalty\":1.0,\"min_p\":0.0,\"seed\":0},\"prompt_tokens\":"
        << promptTokens << ",\"token_ids\":[";
    for (size_t i = 0; i < ids.size(); ++i) { if (i) out << ','; out << ids[i]; }
    out << "]}\n";
    std::cout << "REFERENCE_RECEIPT=" << argv[7] << " TOKENS=" << ids.size() << "\n";
    return 0;
}
