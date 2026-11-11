#pragma once
#include <string>

class AutoUpdate {
public:
    AutoUpdate() = default;
    bool checkAndInstall();
};
