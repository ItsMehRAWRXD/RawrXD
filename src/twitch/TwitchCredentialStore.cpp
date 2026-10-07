/* TwitchCredentialStore.cpp — DPAPI implementation */
#include "TwitchCredentialStore.hpp"

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <dpapi.h>
#include <wincrypt.h>
#pragma comment(lib, "crypt32.lib")
#endif

#include <cstring>
#include <chrono>

namespace RawrXD {
namespace Twitch {

void TwitchCredentialStore::SecureErase(void* ptr, size_t len) noexcept {
    if (!ptr || len == 0) return;
    volatile unsigned char* p = static_cast<volatile unsigned char*>(ptr);
    while (len--) *p++ = 0;
}

bool TwitchCredentialStore::IsTokenValid(const StoredCredentials& creds, uint64_t nowUnix) noexcept {
    if (creds.accessToken.empty()) return false;
    if (creds.expiresAtUnix == 0) return true; /* non-expiring token */
    return (nowUnix + 60) < creds.expiresAtUnix;
}

#ifdef _WIN32

bool TwitchCredentialStore::ProtectData(const std::vector<uint8_t>& plain,
                                        std::vector<uint8_t>& cipher) noexcept {
    DATA_BLOB inBlob{static_cast<DWORD>(plain.size()),
                     const_cast<BYTE*>(plain.data())};
    DATA_BLOB outBlob{};
    if (!CryptProtectData(&inBlob, L"RawrXD_Twitch_Creds", nullptr, nullptr,
                            nullptr, CRYPTPROTECT_UI_FORBIDDEN, &outBlob)) {
        return false;
    }
    cipher.assign(outBlob.pbData, outBlob.pbData + outBlob.cbData);
    LocalFree(outBlob.pbData);
    return true;
}

bool TwitchCredentialStore::UnprotectData(const std::vector<uint8_t>& cipher,
                                          std::vector<uint8_t>& plain) noexcept {
    if (cipher.empty()) return false;
    DATA_BLOB inBlob{static_cast<DWORD>(cipher.size()),
                     const_cast<BYTE*>(cipher.data())};
    DATA_BLOB outBlob{};
    if (!CryptUnprotectData(&inBlob, nullptr, nullptr, nullptr, nullptr,
                            CRYPTPROTECT_UI_FORBIDDEN, &outBlob)) {
        return false;
    }
    plain.assign(outBlob.pbData, outBlob.pbData + outBlob.cbData);
    LocalFree(outBlob.pbData);
    return true;
}

#else
/* Non-Windows: plaintext fallback (not recommended for production) */
bool TwitchCredentialStore::ProtectData(const std::vector<uint8_t>& plain,
                                          std::vector<uint8_t>& cipher) noexcept {
    cipher = plain;
    return true;
}
bool TwitchCredentialStore::UnprotectData(const std::vector<uint8_t>& cipher,
                                          std::vector<uint8_t>& plain) noexcept {
    plain = cipher;
    return true;
}
#endif

bool TwitchCredentialStore::Load(const std::string& path, StoredCredentials& out) noexcept {
    out = {};
    FILE* f = nullptr;
#ifdef _WIN32
    fopen_s(&f, path.c_str(), "rb");
#else
    f = fopen(path.c_str(), "rb");
#endif
    if (!f) return false;
    std::fseek(f, 0, SEEK_END);
    long sz = std::ftell(f);
    std::rewind(f);
    if (sz <= 0) { std::fclose(f); return false; }
    std::vector<uint8_t> cipher(static_cast<size_t>(sz));
    if (std::fread(cipher.data(), 1, cipher.size(), f) != cipher.size()) {
        std::fclose(f);
        return false;
    }
    std::fclose(f);

    std::vector<uint8_t> plain;
    if (!UnprotectData(cipher, plain)) return false;

    /* Parse simple key-value: token\nrefresh\nexpires\nuserid\nlogin */
    std::string text(plain.begin(), plain.end());
    SecureErase(plain.data(), plain.size());

    size_t pos = 0;
    auto next = [&]() -> std::string {
        if (pos >= text.size()) return "";
        size_t n = text.find('\n', pos);
        if (n == std::string::npos) n = text.size();
        std::string line = text.substr(pos, n - pos);
        pos = n + 1;
        return line;
    };
    out.accessToken  = next();
    out.refreshToken = next();
    out.expiresAtUnix = std::strtoull(next().c_str(), nullptr, 10);
    out.botUserId    = next();
    out.botLogin     = next();
    SecureErase(text.data(), text.size());
    return !out.accessToken.empty();
}

bool TwitchCredentialStore::Save(const std::string& path,
                                 const StoredCredentials& in) noexcept {
    std::string text = in.accessToken + "\n" + in.refreshToken + "\n" +
                       std::to_string(in.expiresAtUnix) + "\n" +
                       in.botUserId + "\n" + in.botLogin + "\n";
    std::vector<uint8_t> plain(text.begin(), text.end());
    SecureErase(text.data(), text.size());

    std::vector<uint8_t> cipher;
    if (!ProtectData(plain, cipher)) {
        SecureErase(plain.data(), plain.size());
        return false;
    }
    SecureErase(plain.data(), plain.size());

    FILE* f = nullptr;
#ifdef _WIN32
    fopen_s(&f, path.c_str(), "wb");
#else
    f = fopen(path.c_str(), "wb");
#endif
    if (!f) return false;
    bool ok = (std::fwrite(cipher.data(), 1, cipher.size(), f) == cipher.size());
    std::fclose(f);
    return ok;
}

} // namespace Twitch
} // namespace RawrXD
