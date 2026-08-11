#pragma once

#include <string>
#include <iostream>
#include <sstream>
#include <mutex>

// Minimal Logger for Deep2 components
// Provides static info/warn/error methods compatible with fmt-style formatting
class Logger {
public:
    template<typename... Args>
    static void info(const std::string& fmt, Args... args) {
        log("INFO", fmt, args...);
    }

    template<typename... Args>
    static void warn(const std::string& fmt, Args... args) {
        log("WARN", fmt, args...);
    }

    template<typename... Args>
    static void error(const std::string& fmt, Args... args) {
        log("ERROR", fmt, args...);
    }

    template<typename... Args>
    static void debug(const std::string& fmt, Args... args) {
        log("DEBUG", fmt, args...);
    }

    template<typename... Args>
    static void trace(const std::string& fmt, Args... args) {
        log("TRACE", fmt, args...);
    }

private:
    static std::mutex& getMutex() {
        static std::mutex m;
        return m;
    }

    template<typename T>
    static void formatImpl(std::ostream& os, const std::string& fmt, T value) {
        size_t pos = fmt.find("{}");
        if (pos != std::string::npos) {
            os << fmt.substr(0, pos) << value << fmt.substr(pos + 2);
        } else {
            os << fmt << value;
        }
    }

    template<typename T, typename... Args>
    static void formatImpl(std::ostream& os, const std::string& fmt, T value, Args... args) {
        size_t pos = fmt.find("{}");
        if (pos != std::string::npos) {
            os << fmt.substr(0, pos) << value;
            formatImpl(os, fmt.substr(pos + 2), args...);
        } else {
            os << fmt << value;
            formatImpl(os, "", args...);
        }
    }

    static void formatImpl(std::ostream& os, const std::string& fmt) {
        os << fmt;
    }

    template<typename... Args>
    static void log(const char* level, const std::string& fmt, Args... args) {
        std::lock_guard<std::mutex> lock(getMutex());
        std::ostringstream oss;
        oss << "[" << level << "] ";
        formatImpl(oss, fmt, args...);
        std::cout << oss.str() << std::endl;
    }
};
