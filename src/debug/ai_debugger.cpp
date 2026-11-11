// AI Debugger - Qt-free implementation
#include <iostream>
#include <string>
#include <map>

class AIDebugger {
public:
    AIDebugger() = default;
    
    std::map<std::string, std::string> getDebugInfo() {
        std::map<std::string, std::string> debugInfo;
        debugInfo["locals"] = "[]";
        debugInfo["stack"] = "[]";
        debugInfo["registers"] = "[]";
        return debugInfo;
    }
};

int main() {
    AIDebugger debugger;
    auto info = debugger.getDebugInfo();
    std::cout << "AI Debugger initialized" << std::endl;
    return 0;
}
