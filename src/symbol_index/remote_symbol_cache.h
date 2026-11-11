// ============================================================================
// remote_symbol_cache.h — Cross-Repository Symbol Cache Interface
// ============================================================================

#pragma once

#include <string>
#include <vector>
#include <unordered_map>

namespace RawrXD {
namespace SymbolIndex {

struct RemoteSymbol {
    std::string name;
    std::string kind;
    std::string repository;
    std::string filePath;
    int line;
    int column;
    std::string signature;
    std::string documentation;
    std::string containerName;
};

class RemoteSymbolCache {
public:
    void addRepository(const std::string& repoName, const std::string& localPath);
    bool indexRepository(const std::string& repoName);
    std::vector<RemoteSymbol> findSymbol(const std::string& symbolName);
    std::vector<RemoteSymbol> findSymbolInRepo(const std::string& symbolName,
                                               const std::string& repoName);
    std::vector<RemoteSymbol> getSymbolsInFile(const std::string& repoName,
                                               const std::string& filePath);
    void refreshRepository(const std::string& repoName);
    void clear();
    std::string exportToJson() const;
    bool importFromJson(const std::string& json);
};

} // namespace SymbolIndex
} // namespace RawrXD
