// ExtensionAPI_VSCode_Dispatcher.cpp — API Dispatcher (Batch 5 X02)
#include "ExtensionAPI_VSCode_Internal.h"
#include <iostream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

namespace vscode {

void Window::showInformationMessage(const std::string& message) {
    std::cout << "[VSCodeAPI] Info: " << message << std::endl;
}

void Window::showErrorMessage(const std::string& message) {
    std::cerr << "[VSCodeAPI] Error: " << message << std::endl;
}

void Commands::registerCommand(const std::string& command, std::function<void()> callback) {
    std::cout << "[VSCodeAPI] Registered Command: " << command << std::endl;
}

void Commands::executeCommand(const std::string& command) {
    std::cout << "[VSCodeAPI] Executing Command: " << command << std::endl;
}

} // namespace vscode

namespace RawrXD::Extensions {

class APIDispatcher {
public:
    static void Dispatch(const std::vector<uint8_t>& payload) {
        if (payload.empty()) return;
        try {
            auto j = json::parse(payload.begin(), payload.end());
            std::string method = j.value("method", "");
            if (method == "window.showInformationMessage") {
                std::string msg = j.at("params").at("message");
                vscode::window.showInformationMessage(msg);
            }
            else if (method == "commands.executeCommand") {
                std::string cmd = j.at("params").at("command");
                vscode::commands.executeCommand(cmd);
            }
        } catch (const std::exception& e) {
            std::cerr << "[APIDispatcher] Error: " << e.what() << std::endl;
        }
    }
};

} // namespace RawrXD::Extensions
