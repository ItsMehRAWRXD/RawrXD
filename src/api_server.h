#pragma once
// Stub api_server.h for CLI-only builds

#include <string>

struct AppState;

class APIServer {
public:
    explicit APIServer(AppState&) {}
    bool Start(int) { return true; }
    void Stop() {}
};
