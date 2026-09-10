#include "ProviderKeyStore.hpp"
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <wincred.h>

namespace RawrXD {
namespace Keys {

bool Clear(const char* provider)
{
    if (!IsKnownProvider(provider))
        return false;
    std::string target = std::string("RawrXD/ProviderKey/") + provider;
    CredDeleteA(target.c_str(), CRED_TYPE_GENERIC, 0);
    return true;
}

std::string Mask(const std::string& key)
{
    if (key.empty())
        return "(not set)";
    if (key.size() < 8)
        return "****";
    return key.substr(0, 4) + "****" + key.substr(key.size() - 4);
}

}  // namespace Keys
}  // namespace RawrXD
