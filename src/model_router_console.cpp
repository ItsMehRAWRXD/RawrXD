#include "model_router_console.h"
#include <iostream>

ModelRouterConsole::ModelRouterConsole(void* parent)
    : m_parent(parent)
{
}

void ModelRouterConsole::initialize() {
    std::cout << "ModelRouterConsole initialized" << std::endl;
}

void ModelRouterConsole::logMessage(const std::string& msg) {
    std::cout << "[ModelRouter] " << msg << std::endl;
}
