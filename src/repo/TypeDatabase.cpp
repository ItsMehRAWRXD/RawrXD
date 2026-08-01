// ============================================================================
// TypeDatabase.cpp - Type System Registry
// WORKING IMPLEMENTATION
// ============================================================================

#include "TypeDatabase.hpp"
#include <algorithm>

namespace RawrXD {
namespace IDE {

// ============================================================================
// Type Info Implementation
// ============================================================================

TypeInfo::TypeInfo(const std::string& name, TypeKind kind)
    : name(name), kind(kind), size(0), alignment(0) {}

void TypeInfo::AddMember(const MemberInfo& member) {
    members.push_back(member);
}

void TypeInfo::AddBaseClass(const std::string& baseName) {
    baseClasses.push_back(baseName);
}

void TypeInfo::AddMethod(const MethodInfo& method) {
    methods.push_back(method);
}

bool TypeInfo::IsDerivedFrom(const std::string& baseName) const {
    for (const auto& base : baseClasses) {
        if (base == baseName) return true;
    }
    return false;
}

// ============================================================================
// Type Database Implementation
// ============================================================================

struct TypeDatabase::Impl {
    // Type name -> Type info
    std::unordered_map<std::string, std::shared_ptr<TypeInfo>> types_;
    
    // File path -> types defined in file
    std::unordered_map<std::string, std::vector<std::string>> fileTypes_;
    
    // Primitive types
    std::unordered_set<std::string> primitives_ = {
        "void", "bool", "char", "signed char", "unsigned char",
        "short", "unsigned short", "int", "unsigned int",
        "long", "unsigned long", "long long", "unsigned long long",
        "float", "double", "long double", "wchar_t", "char16_t", "char32_t"
    };
    
    mutable std::shared_mutex mutex_;
};

TypeDatabase::TypeDatabase() : impl_(std::make_unique<Impl>()) {}
TypeDatabase::~TypeDatabase() = default;

void TypeDatabase::RegisterType(std::shared_ptr<TypeInfo> type) {
    std::unique_lock<std::shared_mutex> lock(impl_->mutex_);
    
    impl_->types_[type->name] = type;
    impl_->fileTypes_[type->sourceFile].push_back(type->name);
}

std::shared_ptr<TypeInfo> TypeDatabase::LookupType(const std::string& name) {
    std::shared_lock<std::shared_mutex> lock(impl_->mutex_);
    
    auto it = impl_->types_.find(name);
    if (it != impl_->types_.end()) {
        return it->second;
    }
    return nullptr;
}

std::shared_ptr<TypeInfo> TypeDatabase::GetOrCreateType(const std::string& name, TypeKind kind) {
    std::unique_lock<std::shared_mutex> lock(impl_->mutex_);
    
    auto it = impl_->types_.find(name);
    if (it != impl_->types_.end()) {
        return it->second;
    }
    
    auto type = std::make_shared<TypeInfo>(name, kind);
    impl_->types_[name] = type;
    return type;
}

bool TypeDatabase::IsPrimitive(const std::string& name) const {
    std::shared_lock<std::shared_mutex> lock(impl_->mutex_);
    return impl_->primitives_.count(name) > 0;
}

bool TypeDatabase::IsRegistered(const std::string& name) const {
    std::shared_lock<std::shared_mutex> lock(impl_->mutex_);
    return impl_->types_.count(name) > 0 || impl_->primitives_.count(name) > 0;
}

std::vector<std::shared_ptr<TypeInfo>> TypeDatabase::GetAllTypes() {
    std::shared_lock<std::shared_mutex> lock(impl_->mutex_);
    
    std::vector<std::shared_ptr<TypeInfo>> result;
    for (const auto& [_, type] : impl_->types_) {
        result.push_back(type);
    }
    return result;
}

std::vector<std::shared_ptr<TypeInfo>> TypeDatabase::GetTypesByKind(TypeKind kind) {
    std::shared_lock<std::shared_mutex> lock(impl_->mutex_);
    
    std::vector<std::shared_ptr<TypeInfo>> result;
    for (const auto& [_, type] : impl_->types_) {
        if (type->kind == kind) {
            result.push_back(type);
        }
    }
    return result;
}

std::vector<std::shared_ptr<TypeInfo>> TypeDatabase::GetTypesInFile(const std::string& filePath) {
    std::shared_lock<std::shared_mutex> lock(impl_->mutex_);
    
    std::vector<std::shared_ptr<TypeInfo>> result;
    auto it = impl_->fileTypes_.find(filePath);
    if (it != impl_->fileTypes_.end()) {
        for (const auto& typeName : it->second) {
            auto typeIt = impl_->types_.find(typeName);
            if (typeIt != impl_->types_.end()) {
                result.push_back(typeIt->second);
            }
        }
    }
    return result;
}

std::vector<std::shared_ptr<TypeInfo>> TypeDatabase::GetDerivedTypes(const std::string& baseName) {
    std::shared_lock<std::shared_mutex> lock(impl_->mutex_);
    
    std::vector<std::shared_ptr<TypeInfo>> result;
    for (const auto& [_, type] : impl_->types_) {
        if (type->IsDerivedFrom(baseName)) {
            result.push_back(type);
        }
    }
    return result;
}

std::vector<std::shared_ptr<TypeInfo>> TypeDatabase::GetBaseTypes(const std::string& typeName) {
    std::shared_lock<std::shared_mutex> lock(impl_->mutex_);
    
    std::vector<std::shared_ptr<TypeInfo>> result;
    auto it = impl_->types_.find(typeName);
    if (it != impl_->types_.end()) {
        for (const auto& baseName : it->second->baseClasses) {
            auto baseIt = impl_->types_.find(baseName);
            if (baseIt != impl_->types_.end()) {
                result.push_back(baseIt->second);
            }
        }
    }
    return result;
}

std::optional<MemberInfo> TypeDatabase::FindMember(const std::string& typeName, 
                                                     const std::string& memberName) {
    std::shared_lock<std::shared_mutex> lock(impl_->mutex_);
    
    auto it = impl_->types_.find(typeName);
    if (it != impl_->types_.end()) {
        for (const auto& member : it->second->members) {
            if (member.name == memberName) {
                return member;
            }
        }
    }
    return std::nullopt;
}

std::optional<MethodInfo> TypeDatabase::FindMethod(const std::string& typeName,
                                                     const std::string& methodName) {
    std::shared_lock<std::shared_mutex> lock(impl_->mutex_);
    
    auto it = impl_->types_.find(typeName);
    if (it != impl_->types_.end()) {
        for (const auto& method : it->second->methods) {
            if (method.name == methodName) {
                return method;
            }
        }
    }
    return std::nullopt;
}

std::string TypeDatabase::ResolveTypedef(const std::string& name) {
    std::shared_lock<std::shared_mutex> lock(impl_->mutex_);
    
    auto it = impl_->types_.find(name);
    if (it != impl_->types_.end() && it->second->kind == TypeKind::Typedef) {
        return it->second->underlyingType;
    }
    return name;
}

void TypeDatabase::InvalidateFile(const std::string& filePath) {
    std::unique_lock<std::shared_mutex> lock(impl_->mutex_);
    
    auto it = impl_->fileTypes_.find(filePath);
    if (it != impl_->fileTypes_.end()) {
        for (const auto& typeName : it->second) {
            impl_->types_.erase(typeName);
        }
        impl_->fileTypes_.erase(it);
    }
}

void TypeDatabase::Clear() {
    std::unique_lock<std::shared_mutex> lock(impl_->mutex_);
    impl_->types_.clear();
    impl_->fileTypes_.clear();
}

size_t TypeDatabase::GetTypeCount() const {
    std::shared_lock<std::shared_mutex> lock(impl_->mutex_);
    return impl_->types_.size();
}

// ============================================================================
// Type Inference
// ============================================================================

std::string TypeDatabase::InferTypeFromExpression(const std::string& expression,
                                                  const std::string& contextFile,
                                                  size_t line) {
    // Simple type inference
    // Real implementation would use AST and symbol table
    
    // Check for literals
    if (expression == "true" || expression == "false") return "bool";
    if (expression.find('"') == 0) return "const char*";
    if (expression.find('\'') == 0) return "char";
    
    // Check for numbers
    bool isNumber = true;
    bool hasDecimal = false;
    for (char c : expression) {
        if (!isdigit(c) && c != '.' && c != 'f' && c != 'u' && c != 'l') {
            isNumber = false;
            break;
        }
        if (c == '.') hasDecimal = true;
    }
    
    if (isNumber) {
        if (expression.back() == 'f') return "float";
        if (hasDecimal) return "double";
        if (expression.find("ull") != std::string::npos) return "unsigned long long";
        if (expression.find("ll") != std::string::npos) return "long long";
        if (expression.find("ul") != std::string::npos) return "unsigned long";
        if (expression.find('u') != std::string::npos) return "unsigned int";
        return "int";
    }
    
    // Check for known types
    auto type = LookupType(expression);
    if (type) return type->name;
    
    // Default
    return "auto";
}

bool TypeDatabase::AreTypesCompatible(const std::string& typeA, const std::string& typeB) {
    // Same type
    if (typeA == typeB) return true;
    
    // Check inheritance
    auto bases = GetBaseTypes(typeA);
    for (const auto& base : bases) {
        if (base->name == typeB) return true;
    }
    
    // Check typedefs
    if (ResolveTypedef(typeA) == ResolveTypedef(typeB)) return true;
    
    // Numeric conversions
    static const std::vector<std::string> numericTypes = {
        "bool", "char", "short", "int", "long", "long long",
        "float", "double", "long double"
    };
    
    bool aIsNumeric = std::find(numericTypes.begin(), numericTypes.end(), 
                                ResolveTypedef(typeA)) != numericTypes.end();
    bool bIsNumeric = std::find(numericTypes.begin(), numericTypes.end(),
                                ResolveTypedef(typeB)) != numericTypes.end();
    
    return aIsNumeric && bIsNumeric;
}

std::string TypeDatabase::GetCommonType(const std::string& typeA, const std::string& typeB) {
    if (AreTypesCompatible(typeA, typeB)) {
        // Return the more general type
        // Simplified: just return typeA for now
        return typeA;
    }
    return "";
}

} // namespace IDE
} // namespace RawrXD
