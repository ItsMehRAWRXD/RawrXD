#ifndef MODEL_ROUTER_CONSOLE_H
#define MODEL_ROUTER_CONSOLE_H

#include <string>

class ModelRouterConsole {

public:
    explicit ModelRouterConsole(void* parent = nullptr);
    void initialize();
    void logMessage(const std::string& msg);

private:
    void* m_parent;
};

#endif
