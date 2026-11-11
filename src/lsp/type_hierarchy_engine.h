// ============================================================================
// type_hierarchy_engine.h — Type Hierarchy Interface
// ============================================================================

#pragma once

#include <string>
#include <vector>

namespace RawrXD {
namespace LanguageServices {

struct TypeNode {
    std::string name;
    std::string filePath;
    int line;
    int column;
    std::vector<std::string> baseTypes;
    std::vector<std::string> derivedTypes;
    bool isInterface;
};

class TypeHierarchyEngine {
public:
    TypeNode getTypeHierarchy(const std::string& typeName,
                              const std::string& filePath,
                              int line, int column);
    std::vector<TypeNode> getBaseTypes(const std::string& typeName);
    std::vector<TypeNode> getDerivedTypes(const std::string& typeName);
    std::string renderHierarchy(const std::string& typeName);
    void clearCache();
};

} // namespace LanguageServices
} // namespace RawrXD
