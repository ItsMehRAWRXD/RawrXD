// ============================================================================
// SymbolTable.cpp - Symbol Database with Cross-References
// WORKING IMPLEMENTATION
// ============================================================================

#include "SymbolTable.hpp"
#include <algorithm>
#include <shared_mutex>
#include <optional>
#include <map>

namespace RawrXD {
namespace IDE {

// ============================================================================
// SymbolTable Implementation
// ============================================================================

struct SymbolTable::Impl {
    std::unordered_map<std::string, SymbolInfo> symbols_;
    std::unordered_map<std::string, std::vector<std::string>> byName_;
    std::unordered_map<SymbolKind, std::vector<std::string>> byKind_;
    std::unordered_map<std::string, std::vector<std::string>> byFile_;
    std::unordered_map<std::string, std::vector<std::string>> byParent_;
    std::unordered_map<std::string, std::vector<SymbolLocation>> references_;
    std::map<std::string, std::vector<std::string>> byLocation_;
    mutable std::shared_mutex mutex_;
};

SymbolTable::SymbolTable() : impl_(std::make_unique<Impl>()) {}
SymbolTable::~SymbolTable() = default;

void SymbolTable::Insert(const SymbolInfo& symbol) {
    std::unique_lock<std::shared_mutex> lock(impl_->mutex_);
    std::string id = symbol.qualifiedName.empty() ? symbol.name : symbol.qualifiedName;
    if (impl_->symbols_.count(id)) return;
    SymbolInfo stored = symbol;
    impl_->symbols_[id] = stored;
    impl_->byName_[stored.name].push_back(id);
    impl_->byKind_[stored.kind].push_back(id);
    impl_->byFile_[stored.location.filePath].push_back(id);
    if (!stored.parentScope.empty()) impl_->byParent_[stored.parentScope].push_back(id);
}

void SymbolTable::Remove(const std::string& name, const std::string& filePath) {
    std::unique_lock<std::shared_mutex> lock(impl_->mutex_);
    auto it = impl_->byName_.find(name);
    if (it == impl_->byName_.end()) return;
    for (const auto& id : it->second) {
        auto symIt = impl_->symbols_.find(id);
        if (symIt != impl_->symbols_.end() && symIt->second.location.filePath == filePath)
            impl_->symbols_.erase(symIt);
    }
}

void SymbolTable::RemoveFile(const std::string& filePath) {
    std::unique_lock<std::shared_mutex> lock(impl_->mutex_);
    auto it = impl_->byFile_.find(filePath);
    if (it == impl_->byFile_.end()) return;
    for (const auto& id : it->second) impl_->symbols_.erase(id);
    impl_->byFile_.erase(it);
}

void SymbolTable::Clear() {
    std::unique_lock<std::shared_mutex> lock(impl_->mutex_);
    impl_->symbols_.clear(); impl_->byName_.clear(); impl_->byKind_.clear();
    impl_->byFile_.clear(); impl_->byParent_.clear(); impl_->references_.clear();
    impl_->byLocation_.clear();
}

std::vector<SymbolInfo> SymbolTable::Lookup(const std::string& name) const {
    std::shared_lock<std::shared_mutex> lock(impl_->mutex_);
    std::vector<SymbolInfo> result;
    auto it = impl_->byName_.find(name);
    if (it != impl_->byName_.end()) {
        result.reserve(it->second.size());
        for (const auto& id : it->second) {
            auto symIt = impl_->symbols_.find(id);
            if (symIt != impl_->symbols_.end()) result.push_back(symIt->second);
        }
    }
    return result;
}

std::vector<SymbolInfo> SymbolTable::LookupInScope(const std::string& scope) const {
    std::shared_lock<std::shared_mutex> lock(impl_->mutex_);
    std::vector<SymbolInfo> result;
    auto it = impl_->byParent_.find(scope);
    if (it != impl_->byParent_.end()) {
        result.reserve(it->second.size());
        for (const auto& id : it->second) {
            auto symIt = impl_->symbols_.find(id);
            if (symIt != impl_->symbols_.end()) result.push_back(symIt->second);
        }
    }
    return result;
}

std::vector<SymbolInfo> SymbolTable::GetChildren(const std::string& parentName) const {
    return LookupInScope(parentName);
}

std::vector<SymbolInfo> SymbolTable::GetSymbolsInFile(const std::string& filePath) const {
    std::shared_lock<std::shared_mutex> lock(impl_->mutex_);
    std::vector<SymbolInfo> result;
    auto it = impl_->byFile_.find(filePath);
    if (it != impl_->byFile_.end()) {
        result.reserve(it->second.size());
        for (const auto& id : it->second) {
            auto symIt = impl_->symbols_.find(id);
            if (symIt != impl_->symbols_.end()) result.push_back(symIt->second);
        }
    }
    return result;
}

std::vector<SymbolInfo> SymbolTable::GetSymbolsByKind(SymbolKind kind) const {
    std::shared_lock<std::shared_mutex> lock(impl_->mutex_);
    std::vector<SymbolInfo> result;
    auto it = impl_->byKind_.find(kind);
    if (it != impl_->byKind_.end()) {
        result.reserve(it->second.size());
        for (const auto& id : it->second) {
            auto symIt = impl_->symbols_.find(id);
            if (symIt != impl_->symbols_.end()) result.push_back(symIt->second);
        }
    }
    return result;
}

std::vector<SymbolInfo> SymbolTable::GetAllSymbols() const {
    std::shared_lock<std::shared_mutex> lock(impl_->mutex_);
    std::vector<SymbolInfo> result;
    result.reserve(impl_->symbols_.size());
    for (const auto& pair : impl_->symbols_) result.push_back(pair.second);
    return result;
}

void SymbolTable::AddReference(const std::string& symbolName, const SymbolLocation& ref) {
    std::unique_lock<std::shared_mutex> lock(impl_->mutex_);
    impl_->references_[symbolName].push_back(ref);
}

std::vector<SymbolLocation> SymbolTable::GetReferences(const std::string& symbolName) const {
    std::shared_lock<std::shared_mutex> lock(impl_->mutex_);
    auto it = impl_->references_.find(symbolName);
    return (it != impl_->references_.end()) ? it->second : std::vector<SymbolLocation>{};
}

size_t SymbolTable::GetSymbolCount() const {
    std::shared_lock<std::shared_mutex> lock(impl_->mutex_);
    return impl_->symbols_.size();
}

size_t SymbolTable::GetReferenceCount() const {
    std::shared_lock<std::shared_mutex> lock(impl_->mutex_);
    size_t count = 0;
    for (const auto& pair : impl_->references_) count += pair.second.size();
    return count;
}

} // namespace IDE
} // namespace RawrXD
