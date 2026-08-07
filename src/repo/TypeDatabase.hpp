// ============================================================================
// TypeDatabase.hpp - Type System Registry
// ============================================================================

#pragma once

#include <string>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <memory>
#include <optional>
#include <shared_mutex>

namespace RawrXD {
namespace IDE {

enum class TypeKind {
    Class, Struct, Enum, Union, Typedef,
    Using, Template, Concept, Interface, Primitive
};

struct MemberInfo {
    std::string name;
    std::string type;
    size_t offset;
    size_t size;
    bool isStatic;
    bool isConst;
    std::string access; // "public", "private", "protected"
};

struct MethodInfo {
    std::string name;
    std::string returnType;
    std::vector<std::string> parameters;
    bool isVirtual;
    bool isStatic;
    bool isConst;
    bool isOverride;
    std::string access;
};

struct TypeInfo {
    std::string name;
    std::string qualifiedName;
    TypeKind kind;
    size_t size;
    size_t alignment;
    std::string sourceFile;
    std::string underlyingType; // For typedefs
    std::vector<MemberInfo> members;
    std::vector<std::string> baseClasses;
    std::vector<MethodInfo> methods;

    TypeInfo(const std::string& name, TypeKind kind);
    void AddMember(const MemberInfo& member);
    void AddBaseClass(const std::string& baseName);
    void AddMethod(const MethodInfo& method);
    bool IsDerivedFrom(const std::string& baseName) const;
};

class TypeDatabase {
public:
    TypeDatabase();
    ~TypeDatabase();

    void RegisterType(std::shared_ptr<TypeInfo> type);
    std::shared_ptr<TypeInfo> LookupType(const std::string& name);
    std::shared_ptr<TypeInfo> GetOrCreateType(const std::string& name, TypeKind kind);
    bool IsPrimitive(const std::string& name) const;
    bool IsRegistered(const std::string& name) const;

    std::vector<std::shared_ptr<TypeInfo>> GetAllTypes();
    std::vector<std::shared_ptr<TypeInfo>> GetTypesByKind(TypeKind kind);
    std::vector<std::shared_ptr<TypeInfo>> GetTypesInFile(const std::string& filePath);
    std::vector<std::shared_ptr<TypeInfo>> GetDerivedTypes(const std::string& baseName);
    std::vector<std::shared_ptr<TypeInfo>> GetBaseTypes(const std::string& typeName);

    std::optional<MemberInfo> FindMember(const std::string& typeName, const std::string& memberName);
    std::optional<MethodInfo> FindMethod(const std::string& typeName, const std::string& methodName);
    std::string ResolveTypedef(const std::string& name);

    void InvalidateFile(const std::string& filePath);
    void Clear();
    size_t GetTypeCount() const;

    // Type inference
    std::string InferTypeFromExpression(const std::string& expression,
                                        const std::string& contextFile = "",
                                        size_t line = 0);
    bool AreTypesCompatible(const std::string& typeA, const std::string& typeB);
    std::string GetCommonType(const std::string& typeA, const std::string& typeB);

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace IDE
} // namespace RawrXD
