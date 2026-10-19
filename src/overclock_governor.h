#pragma once
// Stub overclock_governor.h for CLI-only builds

struct AppState;

class OverclockGovernor {
public:
    void Start(const AppState&) {}
    void Stop() {}
};
