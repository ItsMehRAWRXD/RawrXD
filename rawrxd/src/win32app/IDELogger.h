#pragma once
#include <string>

// Minimal IDELogger for enterprise_license.cpp
class IDELogger {
public:
    static void log(const std::string& msg);
    static void error(const std::string& msg);
    static void warn(const std::string& msg);
    static void info(const std::string& msg);
};
