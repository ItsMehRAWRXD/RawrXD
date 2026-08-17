#pragma once
// BSMSymbolResolver — Binary Symbol Map resolver
// Provides symbol lookup for the hot-patching and RE bridge subsystems.
// Real implementation is in BSMSymbolResolver.cpp (DbgHelp + PE exports).

#include <string>
#include <cstdint>
#include <vector>

namespace RawrXD {
namespace Runtime {

struct BSMSymbol {
    std::string name;
    uint64_t    address = 0;
    uint32_t    size    = 0;
    bool        isExported = false;
};

class BSMSymbolResolver {
public:
    BSMSymbolResolver() = default;

    static BSMSymbolResolver& instance();

    bool LoadFromModule(const std::string& modulePath);
    void* resolveSync(const std::string& name);
    bool ResolveByName(const std::string& name, BSMSymbol& out) const;
    bool ResolveByAddress(uint64_t addr, BSMSymbol& out) const;
    std::vector<BSMSymbol> EnumerateExports() const;
    const std::string& GetModulePath() const { return m_modulePath; }

private:
    std::string m_modulePath;
    std::vector<BSMSymbol> m_symbols;
};

} // namespace Runtime
} // namespace RawrXD
