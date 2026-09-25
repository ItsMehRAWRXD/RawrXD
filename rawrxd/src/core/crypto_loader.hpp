#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include <memory>
#include <optional>

namespace rawrxd {

enum class CryptoFormat {
    Raw = 0,
    PEM = 1,
    DER = 2,
    Hex = 3,
    Base64 = 4
};

struct CryptoKey {
    std::vector<uint8_t> data;
    CryptoFormat format = CryptoFormat::Raw;
    std::string algorithm;
    uint32_t key_size_bits = 0;
    bool is_private = false;
};

struct CryptoSignature {
    std::vector<uint8_t> signature;
    std::string algorithm;
    bool valid = false;
};

struct CryptoHash {
    std::vector<uint8_t> digest;
    std::string algorithm;
    uint32_t digest_size = 0;
};

class CryptoLoader {
public:
    CryptoLoader();
    ~CryptoLoader();

    bool LoadKeyFromFile(const std::string& path, CryptoFormat format = CryptoFormat::Raw);
    bool LoadKeyFromMemory(const std::vector<uint8_t>& data, CryptoFormat format = CryptoFormat::Raw);

    bool GenerateKeyPair(uint32_t key_size_bits, const std::string& algorithm = "AES-256-GCM");

    bool Encrypt(const std::vector<uint8_t>& plaintext,
                 std::vector<uint8_t>& ciphertext,
                 std::vector<uint8_t>& iv);
    bool Decrypt(const std::vector<uint8_t>& ciphertext,
                 const std::vector<uint8_t>& iv,
                 std::vector<uint8_t>& plaintext);

    CryptoHash Hash(const std::vector<uint8_t>& data, const std::string& algorithm = "SHA-256");
    CryptoHash HashString(const std::string& data, const std::string& algorithm = "SHA-256");

    bool Sign(const std::vector<uint8_t>& data, CryptoSignature& out);
    bool Verify(const std::vector<uint8_t>& data, const CryptoSignature& sig);

    void SetKey(const CryptoKey& key);
    const CryptoKey* GetKey() const;

    void Unload();

    bool IsLoaded() const;

    static std::vector<uint8_t> GenerateRandomBytes(size_t count);
    static std::string ToHex(const std::vector<uint8_t>& data);
    static std::vector<uint8_t> FromHex(const std::string& hex);
    static std::string ToBase64(const std::vector<uint8_t>& data);
    static std::vector<uint8_t> FromBase64(const std::string& b64);

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

extern CryptoLoader g_CryptoLoader;

} // namespace rawrxd
