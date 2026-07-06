// tools/cli_main.cpp - Full CLI launcher with Ollama integration
// For full chat + agentic CLI (chat, /agent, /smoke, /tools, HTTP API):
//   cmake -B build_ide -G Ninja && cmake --build build_ide --target RawrXD_CLI
// See Ship/CLI_PARITY.md for details.

#include <windows.h>
#include <wininet.h>
#include <iostream>
#include <string>
#include <vector>
#include <sstream>
#include <json/json.hpp>

#pragma comment(lib, "wininet.lib")

using json = nlohmann::json;

static std::string HttpPost(const std::string& url, const std::string& data) {
    HINTERNET hInternet = InternetOpenA("RawrXD-CLI/1.0", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (!hInternet) return "";
    
    URL_COMPONENTSA urlComp = {0};
    urlComp.dwStructSize = sizeof(urlComp);
    char hostName[256] = {0}, urlPath[1024] = {0};
    urlComp.lpszHostName = hostName;
    urlComp.dwHostNameLength = sizeof(hostName);
    urlComp.lpszUrlPath = urlPath;
    urlComp.dwUrlPathLength = sizeof(urlPath);
    
    if (!InternetCrackUrlA(url.c_str(), 0, 0, &urlComp)) {
        InternetCloseHandle(hInternet);
        return "";
    }
    
    HINTERNET hConnect = InternetConnectA(hInternet, hostName, urlComp.nPort, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    if (!hConnect) {
        InternetCloseHandle(hInternet);
        return "";
    }
    
    HINTERNET hRequest = HttpOpenRequestA(hConnect, "POST", urlPath, NULL, NULL, NULL, 
                                          INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE, 0);
    if (!hRequest) {
        InternetCloseHandle(hConnect);
        InternetCloseHandle(hInternet);
        return "";
    }
    
    std::string headers = "Content-Type: application/json\r\n";
    HttpSendRequestA(hRequest, headers.c_str(), (DWORD)headers.length(), (LPVOID)data.c_str(), (DWORD)data.length());
    
    std::string response;
    char buffer[4096];
    DWORD bytesRead;
    while (InternetReadFile(hRequest, buffer, sizeof(buffer) - 1, &bytesRead) && bytesRead > 0) {
        buffer[bytesRead] = '\0';
        response += buffer;
    }
    
    InternetCloseHandle(hRequest);
    InternetCloseHandle(hConnect);
    InternetCloseHandle(hInternet);
    return response;
}

static std::string HttpGet(const std::string& url) {
    HINTERNET hInternet = InternetOpenA("RawrXD-CLI/1.0", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (!hInternet) return "";
    
    HINTERNET hUrl = InternetOpenUrlA(hInternet, url.c_str(), NULL, 0, 
                                      INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE, 0);
    if (!hUrl) {
        InternetCloseHandle(hInternet);
        return "";
    }
    
    std::string response;
    char buffer[4096];
    DWORD bytesRead;
    while (InternetReadFile(hUrl, buffer, sizeof(buffer) - 1, &bytesRead) && bytesRead > 0) {
        buffer[bytesRead] = '\0';
        response += buffer;
    }
    
    InternetCloseHandle(hUrl);
    InternetCloseHandle(hInternet);
    return response;
}

static std::string QueryOllama(const std::string& prompt, const std::string& model = "phi3:mini") {
    json request;
    request["model"] = model;
    request["prompt"] = prompt;
    request["stream"] = false;
    
    std::string response = HttpPost("http://localhost:11434/api/generate", request.dump());
    if (response.empty()) {
        return "Error: Could not connect to Ollama. Is it running on localhost:11434?";
    }
    
    try {
        json j = json::parse(response);
        if (j.contains("response")) {
            return j["response"].get<std::string>();
        }
        if (j.contains("error")) {
            return "Error: " + j["error"].get<std::string>();
        }
    } catch (...) {
        return "Error: Failed to parse response";
    }
    
    return response;
}

static std::vector<std::string> ListOllamaModels() {
    std::vector<std::string> models;
    std::string response = HttpGet("http://localhost:11434/api/tags");
    
    if (response.empty()) return models;
    
    try {
        json j = json::parse(response);
        if (j.contains("models")) {
            for (const auto& model : j["models"]) {
                if (model.contains("name")) {
                    models.push_back(model["name"].get<std::string>());
                }
            }
        }
    } catch (...) {}
    
    return models;
}

static void PrintHelp() {
    std::cout << "RawrXD CLI v1.0 - Full Ollama Integration\n\n";
    std::cout << "Usage:\n";
    std::cout << "  RawrXD_CLI.exe                    - Interactive chat mode\n";
    std::cout << "  RawrXD_CLI.exe <prompt>           - Single query mode\n";
    std::cout << "  RawrXD_CLI.exe --models           - List available models\n";
    std::cout << "  RawrXD_CLI.exe --model <name>     - Use specific model\n";
    std::cout << "  RawrXD_CLI.exe --help, -h         - Show this help\n";
    std::cout << "\nExamples:\n";
    std::cout << "  RawrXD_CLI.exe \"Hello, how are you?\"\n";
    std::cout << "  RawrXD_CLI.exe --model llama3.2:3b \"Explain quantum computing\"\n";
    std::cout << "\n";
}

static void InteractiveChat(const std::string& model) {
    std::cout << "RawrXD Interactive Chat Mode\n";
    std::cout << "Using model: " << model << "\n";
    std::cout << "Type 'exit' or 'quit' to exit.\n\n";
    
    std::vector<std::pair<std::string, std::string>> history;
    
    while (true) {
        std::cout << "> ";
        std::string input;
        std::getline(std::cin, input);
        
        if (input == "exit" || input == "quit") break;
        if (input.empty()) continue;
        
        // Build conversation context
        std::string context = "Previous conversation:\n";
        for (const auto& [user, assistant] : history) {
            context += "User: " + user + "\n";
            context += "Assistant: " + assistant + "\n";
        }
        context += "User: " + input + "\nAssistant:";
        
        std::cout << "Thinking...\n";
        std::string response = QueryOllama(context, model);
        
        std::cout << "\n" << response << "\n\n";
        
        history.push_back({input, response});
        if (history.size() > 10) {
            history.erase(history.begin());
        }
    }
}

int main(int argc, char* argv[]) {
    std::string model = "phi3:mini";
    std::string prompt;
    bool listModels = false;
    bool interactive = true;
    
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        
        if (arg == "--help" || arg == "-h") {
            PrintHelp();
            return 0;
        }
        else if (arg == "--models") {
            listModels = true;
            interactive = false;
        }
        else if (arg == "--model" && i + 1 < argc) {
            model = argv[++i];
        }
        else if (!arg.empty() && arg[0] != '-') {
            if (prompt.empty()) {
                prompt = arg;
            } else {
                prompt += " " + arg;
            }
            interactive = false;
        }
    }
    
    if (listModels) {
        auto models = ListOllamaModels();
        if (models.empty()) {
            std::cout << "No models found or Ollama not running.\n";
            std::cout << "Make sure Ollama is installed and running on localhost:11434\n";
        } else {
            std::cout << "Available models:\n";
            for (const auto& m : models) {
                std::cout << "  - " << m << "\n";
            }
        }
        return 0;
    }
    
    if (interactive) {
        InteractiveChat(model);
    } else {
        std::cout << "Querying " << model << "...\n\n";
        std::string response = QueryOllama(prompt, model);
        std::cout << response << "\n";
    }
    
    return 0;
}
