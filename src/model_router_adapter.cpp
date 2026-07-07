#include "model_router_adapter.h"
#include <iostream>

ModelRouterAdapter::ModelRouterAdapter(void* parent)
    : m_parent(parent)
    , m_router(nullptr)
{
}

void* ModelRouterAdapter::getRouter() {
    return m_router;
}

void* ModelRouterAdapter::createRouter() {
    return nullptr;
}

void* ModelRouterAdapter::getModel(const std::string& name) {
    (void)name;
    return nullptr;
}

void* ModelRouterAdapter::loadModel(const std::string& path) {
    (void)path;
    return nullptr;
}
