#include "model_router_console.h"
#include <iostream>

int main() {
    ModelRouterConsole console(nullptr);
    console.initialize();
    console.logMessage("Test message");
    return 0;
}
