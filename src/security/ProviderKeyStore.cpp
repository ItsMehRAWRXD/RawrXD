#include "ProviderKeyStore.hpp"
#include <cstring>
#include <vector>
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <wincrypt.h>
#include <wincred.h>
#pragma comment(lib, "Crypt32.lib")
#pragma comment(lib, "Advapi32.lib")

namespace RawrXD {
namespace Keys {
namespace {

const char* kProviders[] = {kOllama, kCursor, kGitHubCopilot};

std::string targetName(const char* provider)
{
    return std::string("RawrXD/ProviderKey/") + provider;
}

bool dpapiProtect(const std::string& plain, std::vector<BYTE>& out)
{
    DATA_BLOB in{(DWORD)plain.size(), (BYTE*)plain.data()};
    DATA_BLOB blob{};
    if (!CryptProtectData(&in, L"RawrXD ProviderKey", nullptr, nullptr, nullptr, 0, &blob))
        return false;
    out.assign(blob.pbData, blob.pbData + blob.cbData);
    LocalFree(blob.pbData);
    return true;
}

}  // namespace

bool IsKnownProvider(const char* provider) noexcept
{
    if (!provider || !provider[0])
        return false;
    for (const char* p : kProviders) {
        if (std::strcmp(provider, p) == 0)
            return true;
    }
    return false;
}

const char* const* KnownProviders(std::size_t* count) noexcept
{
    if (count)
        *count = sizeof(kProviders) / sizeof(kProviders[0]);
    return kProviders;
}

bool Set(const char* provider, const std::string& key)
{
    if (!IsKnownProvider(provider) || key.empty())
        return false;
    std::vector<BYTE> enc;
    if (!dpapiProtect(key, enc))
        return false;
    std::string target = targetName(provider);
    CREDENTIALA cred{};
    cred.Type = CRED_TYPE_GENERIC;
    cred.TargetName = const_cast<char*>(target.c_str());
    cred.CredentialBlobSize = (DWORD)enc.size();
    cred.CredentialBlob = enc.data();
    cred.Persist = CRED_PERSIST_LOCAL_MACHINE;
    cred.UserName = const_cast<char*>("RawrXD");
    return CredWriteA(&cred, 0) != 0;
}

}  // namespace Keys
}  // namespace RawrXD
