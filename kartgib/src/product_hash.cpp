#include <windows.h>
#include <bcrypt.h>
#include <fstream>
#include <vector>
#pragma comment(lib, "bcrypt.lib")

void exeSha256(char out[65]) {
    wchar_t path[32768]{};
    GetModuleFileNameW(nullptr, path, 32768);
    std::ifstream file(path, std::ios::binary);
    std::vector<unsigned char> bytes((std::istreambuf_iterator<char>(file)), {});
    BCRYPT_ALG_HANDLE alg = nullptr;
    BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0);
    DWORD objLen = 0, cb = 0;
    BCryptGetProperty(alg, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&objLen), 4, &cb, 0);
    std::vector<UCHAR> obj(objLen), hash(32);
    BCRYPT_HASH_HANDLE handle = nullptr;
    BCryptCreateHash(alg, &handle, obj.data(), objLen, nullptr, 0, 0);
    BCryptHashData(handle, bytes.data(), static_cast<ULONG>(bytes.size()), 0);
    BCryptFinishHash(handle, hash.data(), 32, 0);
    BCryptDestroyHash(handle);
    BCryptCloseAlgorithmProvider(alg, 0);
    const char* hex = "0123456789ABCDEF";
    for (int i = 0; i < 32; ++i) { out[i * 2] = hex[hash[i] >> 4]; out[i * 2 + 1] = hex[hash[i] & 15]; }
    out[64] = 0;
}
