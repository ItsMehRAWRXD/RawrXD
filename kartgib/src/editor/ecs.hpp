#pragma once

#include <cstdint>
#include <vector>
#include <unordered_map>
#include <typeindex>
#include <memory>
#include <string>
#include <functional>
#include <array>
#include <algorithm>
#include <cassert>

namespace kartgib::editor {

using EntityID = uint64_t;
using ComponentID = uint32_t;
constexpr EntityID INVALID_ENTITY = 0;
constexpr ComponentID INVALID_COMPONENT = 0;
constexpr size_t MAX_COMPONENTS = 64;
constexpr size_t INITIAL_ENTITY_CAPACITY = 1024;

struct ComponentPool {
    virtual ~ComponentPool() = default;
    virtual void remove(EntityID entity) = 0;
    virtual bool has(EntityID entity) const = 0;
    virtual size_t size() const = 0;
    virtual void clear() = 0;
};

template<typename T>
class ComponentPoolImpl : public ComponentPool {
    std::unordered_map<EntityID, T> components_;
    std::vector<EntityID> entityList_;

public:
    template<typename... Args>
    T& add(EntityID entity, Args&&... args) {
        auto [it, inserted] = components_.emplace(entity, T(std::forward<Args>(args)...));
        if (inserted) {
            entityList_.push_back(entity);
        }
        return it->second;
    }

    void remove(EntityID entity) override {
        components_.erase(entity);
        entityList_.erase(
            std::remove(entityList_.begin(), entityList_.end(), entity),
            entityList_.end()
        );
    }

    bool has(EntityID entity) const override {
        return components_.find(entity) != components_.end();
    }

    T* get(EntityID entity) {
        auto it = components_.find(entity);
        return it != components_.end() ? &it->second : nullptr;
    }

    const T* get(EntityID entity) const {
        auto it = components_.find(entity);
        return it != components_.end() ? &it->second : nullptr;
    }

    size_t size() const override { return components_.size(); }

    void clear() override {
        components_.clear();
        entityList_.clear();
    }

    const std::vector<EntityID>& entities() const { return entityList_; }
    std::unordered_map<EntityID, T>& components() { return components_; }
};

class EntityManager {
    EntityID nextEntityID_ = 1;
    std::vector<EntityID> freeEntityIDs_;
    std::vector<std::string> entityNames_;
    std::vector<EntityID> parentEntities_;
    std::vector<std::vector<EntityID>> childrenEntities_;
    std::unordered_map<EntityID, std::vector<std::type_index>> entityComponents_;
    std::vector<bool> entityActive_;
    std::vector<bool> entityDestroyed_;

public:
    EntityManager() {
        entityNames_.reserve(INITIAL_ENTITY_CAPACITY);
        parentEntities_.reserve(INITIAL_ENTITY_CAPACITY);
        childrenEntities_.reserve(INITIAL_ENTITY_CAPACITY);
        entityActive_.reserve(INITIAL_ENTITY_CAPACITY);
        entityDestroyed_.reserve(INITIAL_ENTITY_CAPACITY);
    }

    EntityID createEntity(const std::string& name = "Entity") {
        EntityID id;
        if (!freeEntityIDs_.empty()) {
            id = freeEntityIDs_.back();
            freeEntityIDs_.pop_back();
        } else {
            id = nextEntityID_++;
        }

        ensureCapacity(id);
        entityNames_[id] = name;
        parentEntities_[id] = INVALID_ENTITY;
        entityActive_[id] = true;
        entityDestroyed_[id] = false;
        entityComponents_[id] = {};
        return id;
    }

    void destroyEntity(EntityID entity) {
        if (entity >= entityDestroyed_.size() || entityDestroyed_[entity]) return;
        
        // Destroy all children first
        auto& children = childrenEntities_[entity];
        for (auto child : children) {
            destroyEntity(child);
        }
        children.clear();

        // Remove from parent
        EntityID parent = parentEntities_[entity];
        if (parent != INVALID_ENTITY) {
            auto& parentChildren = childrenEntities_[parent];
            parentChildren.erase(
                std::remove(parentChildren.begin(), parentChildren.end(), entity),
                parentChildren.end()
            );
        }

        entityDestroyed_[entity] = true;
        entityActive_[entity] = false;
        entityNames_[entity].clear();
        parentEntities_[entity] = INVALID_ENTITY;
        entityComponents_[entity].clear();
        freeEntityIDs_.push_back(entity);
    }

    void setParent(EntityID child, EntityID parent) {
        if (child == parent || child == INVALID_ENTITY) return;
        
        EntityID oldParent = parentEntities_[child];
        if (oldParent != INVALID_ENTITY) {
            auto& oldChildren = childrenEntities_[oldParent];
            oldChildren.erase(
                std::remove(oldChildren.begin(), oldChildren.end(), child),
                oldChildren.end()
            );
        }

        if (parent != INVALID_ENTITY) {
            childrenEntities_[parent].push_back(child);
        }
        parentEntities_[child] = parent;
    }

    EntityID getParent(EntityID entity) const {
        if (entity >= parentEntities_.size()) return INVALID_ENTITY;
        return parentEntities_[entity];
    }

    const std::vector<EntityID>& getChildren(EntityID entity) const {
        static const std::vector<EntityID> empty;
        if (entity >= childrenEntities_.size()) return empty;
        return childrenEntities_[entity];
    }

    void setName(EntityID entity, const std::string& name) {
        if (entity < entityNames_.size()) entityNames_[entity] = name;
    }

    const std::string& getName(EntityID entity) const {
        static const std::string empty;
        if (entity >= entityNames_.size()) return empty;
        return entityNames_[entity];
    }

    void setActive(EntityID entity, bool active) {
        if (entity < entityActive_.size()) entityActive_[entity] = active;
    }

    bool isActive(EntityID entity) const {
        if (entity >= entityActive_.size()) return false;
        return entityActive_[entity] && !entityDestroyed_[entity];
    }

    bool isDestroyed(EntityID entity) const {
        if (entity >= entityDestroyed_.size()) return false;
        return entityDestroyed_[entity];
    }

    EntityID findByName(const std::string& name) const {
        for (size_t i = 1; i < entityNames_.size(); ++i) {
            if (!entityDestroyed_[i] && entityNames_[i] == name) {
                return static_cast<EntityID>(i);
            }
        }
        return INVALID_ENTITY;
    }

    size_t getEntityCount() const {
        size_t count = 0;
        for (size_t i = 1; i < entityDestroyed_.size(); ++i) {
            if (!entityDestroyed_[i]) ++count;
        }
        return count;
    }

    void registerComponent(EntityID entity, const std::type_index& type) {
        entityComponents_[entity].push_back(type);
    }

    void unregisterComponent(EntityID entity, const std::type_index& type) {
        auto& comps = entityComponents_[entity];
        comps.erase(std::remove(comps.begin(), comps.end(), type), comps.end());
    }

    const std::vector<std::type_index>& getComponents(EntityID entity) const {
        static const std::vector<std::type_index> empty;
        auto it = entityComponents_.find(entity);
        return it != entityComponents_.end() ? it->second : empty;
    }

private:
    void ensureCapacity(EntityID entity) {
        size_t size = static_cast<size_t>(entity) + 1;
        if (entityNames_.size() < size) {
            entityNames_.resize(size);
            parentEntities_.resize(size, INVALID_ENTITY);
            childrenEntities_.resize(size);
            entityActive_.resize(size, false);
            entityDestroyed_.resize(size, false);
        }
    }
};

class ComponentManager {
    std::unordered_map<std::type_index, std::unique_ptr<ComponentPool>> pools_;
    EntityManager* entityManager_ = nullptr;

public:
    explicit ComponentManager(EntityManager* em) : entityManager_(em) {}

    template<typename T>
    ComponentPoolImpl<T>* getPool() {
        std::type_index type(typeid(T));
        auto it = pools_.find(type);
        if (it == pools_.end()) {
            auto pool = std::make_unique<ComponentPoolImpl<T>>();
            auto* ptr = pool.get();
            pools_.emplace(type, std::move(pool));
            return ptr;
        }
        return static_cast<ComponentPoolImpl<T>*>(it->second.get());
    }

    template<typename T, typename... Args>
    T& addComponent(EntityID entity, Args&&... args) {
        if (!entityManager_->isActive(entity)) return T();
        auto* pool = getPool<T>();
        T& component = pool->add(entity, std::forward<Args>(args)...);
        entityManager_->registerComponent(entity, std::type_index(typeid(T)));
        return component;
    }

    template<typename T>
    T* getComponent(EntityID entity) {
        if (!entityManager_->isActive(entity)) return nullptr;
        auto* pool = getPool<T>();
        return pool->get(entity);
    }

    template<typename T>
    void removeComponent(EntityID entity) {
        auto type = std::type_index(typeid(T));
        auto it = pools_.find(type);
        if (it != pools_.end()) {
            it->second->remove(entity);
        }
        entityManager_->unregisterComponent(entity, type);
    }

    template<typename T>
    bool hasComponent(EntityID entity) const {
        if (!entityManager_->isActive(entity)) return false;
        auto it = pools_.find(std::type_index(typeid(T)));
        if (it == pools_.end()) return false;
        return it->second->has(entity);
    }

    void removeAllComponents(EntityID entity) {
        for (auto& [type, pool] : pools_) {
            pool->remove(entity);
        }
        if (entityManager_) {
            entityManager_->entityComponents_[entity].clear();
        }
    }

    void clearAll() {
        for (auto& [type, pool] : pools_) {
            pool->clear();
        }
    }

    size_t getComponentCount(EntityID entity) const {
        if (!entityManager_ || !entityManager_->isActive(entity)) return 0;
        return entityManager_->entityComponents_.at(entity).size();
    }
};

} // namespace kartgib::editor