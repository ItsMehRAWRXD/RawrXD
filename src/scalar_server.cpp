#include "scalar_server.h"
#include <iostream>

ScalarServer::ScalarServer(void* parent)
    : m_parent(parent)
{
}

void ScalarServer::start() {
    std::cout << "ScalarServer started" << std::endl;
}

void ScalarServer::stop() {
    std::cout << "ScalarServer stopped" << std::endl;
}
