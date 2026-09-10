#include "ProviderKeyStore.hpp"
#include <cstdlib>
#include <cstring>
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <wincrypt.h>
#include <wincred.h>

namespace RawrXD {
namespace Keys {
namespace {

std::string targetName(const char* provider)
{
    return std::string("RawrXD/ProviderKey/") + provider;
}

bool dpapiUnprotect(const BYTE* data, DWORD len, std::string& out)
{
    DATA_BLOB in{len, (BYTE*)data};
    DATA_BLOB blob{};
    if (!CryptUnprotectData(&in, nullptr, nullptr, nullptr, nullptr, 0, &blob))
        return false;
    out.assign((char*)blob.pbData, (char*)blob.pbData + blob.cbData);
    LocalFree(blob.pbData);
    return true;
}

std::string envFallback(const char* provider)
{
    if (std::strcmp(provider, kGitHubCopilot) == 0) {
        for (const char* v : {"COPILOT_GITHUB_TOKEN", "GH_TOKEN", "GITHUB_TOKEN"}) {
            const char* e = std::getenv(v);
            if (e && e[0])
                return e;
        }
        return {};
    }
    const char* name = (std::strcmp(provider, kOllama) == 0)   ? "OLLAMA_API_KEY"
                       : (std::strcmp(provider, kCursor) == 0) ? "CURSOR_API_KEY"
                                                               : nullptr;
    if (!name)
        return {};
    const char* e = std::getenv(name);
    return (e && e[0]) ? std::string(e) : std::string();
}

bool readStore(const char* provider, std::string& out)
{
    PCREDENTIALA pCred = nullptr;
    if (!CredReadA(targetName(provider).c_str(), CRED_TYPE_GENERIC, 0, &pCred) || !pCred)
        return false;
    bool ok = dpapiUnprotect(pCred->CredentialBlob, pCred->CredentialBlobSize, out);
    CredFree(pCred);
    return ok && !out.empty();
}

}  // namespace

ResolvedCredential Resolve(const char* provider)
{
    ResolvedCredential r;
    if (!IsKnownProvider(provider))
        return r;
    std::string storeVal;
    if (readStore(provider, storeVal)) {
        r.source = CredentialSource::Store;
        r.value = std::move(storeVal);
        return r;
    }
    std::string envVal = envFallback(provider);
    if (!envVal.empty()) {
        r.source = CredentialSource::Env;
        r.value = std::move(envVal);
    }
    return r;
}

std::string Get(const char* provider) { return Resolve(provider).value; }
bool Has(const char* provider) { return Resolve(provider).source != CredentialSource::None; }

bool HasStore(const char* provider)
{
    if (!IsKnownProvider(provider))
        return false;
    std::string unused;
    return readStore(provider, unused);
}

}  // namespace Keys
}  // namespace RawrXD
