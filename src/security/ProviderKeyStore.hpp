#pragma once
// Zero-dep provider API keys: CredWrite + DPAPI. No nlohmann/Qt/npm.
//
// CREDENTIAL_RESOLUTION (sealed):
//   1. ProviderKeyStore (CredWrite/DPAPI)
//   2. provider-specific environment fallback
//   3. NO_CREDENTIAL
// NO_BACKENDS_JSON_SECRET_FALLBACK=1
// NO_SECRET_LOGGING=1
#include <cstddef>
#include <cstdint>
#include <string>

namespace RawrXD {
namespace Keys {

inline constexpr const char* kOllama = "ollama";
inline constexpr const char* kCursor = "cursor";
inline constexpr const char* kGitHubCopilot = "github_copilot";

enum class CredentialSource : std::uint8_t {
    None = 0,
    Store = 1,
    Env = 2
};

inline const char* CredentialSourceName(CredentialSource s) noexcept
{
    switch (s) {
        case CredentialSource::Store: return "STORE";
        case CredentialSource::Env: return "ENV";
        default: return "NO_CREDENTIAL";
    }
}

struct ResolvedCredential {
    CredentialSource source = CredentialSource::None;
    std::string value;
};

bool IsKnownProvider(const char* provider) noexcept;
const char* const* KnownProviders(std::size_t* count) noexcept;

bool Set(const char* provider, const std::string& key);
bool Clear(const char* provider);
bool HasStore(const char* provider);  // CredWrite entry only (ignores env)
ResolvedCredential Resolve(const char* provider);
std::string Get(const char* provider);  // Resolve().value
bool Has(const char* provider);
std::string Mask(const std::string& key);

}  // namespace Keys
}  // namespace RawrXD
