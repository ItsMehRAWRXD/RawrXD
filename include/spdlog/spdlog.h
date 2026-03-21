#pragma once
#include <iostream>
#include <string>
#include <memory>
#include <vector>

namespace spdlog {
    namespace level {
        enum level_enum {
            trace,
            debug,
            info,
            warn,
            err,
            critical,
            off
        };
        inline level_enum from_str(const std::string&) { return info; }
    }

    // Forward declare logger for sink_ptr
    class logger;
    
    // Sink types (stubs)
    namespace sinks {
        class sink {
        public:
            virtual ~sink() = default;
        };
        
        class basic_file_sink_mt : public sink {
        public:
            basic_file_sink_mt(const std::string& /*filename*/, bool /*truncate*/ = false) {}
        };
        
        class stdout_color_sink_mt : public sink {
        public:
            stdout_color_sink_mt() {}
        };
    }
    
    using sink_ptr = std::shared_ptr<sinks::sink>;

    class logger {
    public:
        logger() = default;
        logger(const std::string& /*name*/, 
               std::vector<sink_ptr>::iterator /*begin*/, 
               std::vector<sink_ptr>::iterator /*end*/) {}
               
        template<typename... Args>
        void info(const std::string& fmt, Args&&... args) {
            std::cout << "[INFO] " << fmt << std::endl;
        }
        template<typename... Args>
        void error(const std::string& fmt, Args&&... args) {
            std::cerr << "[ERROR] " << fmt << std::endl;
        }
        
        template<typename... Args>
        void log(level::level_enum lvl, const std::string& fmt, Args&&... args) {
             std::cout << "[LOG] " << fmt << std::endl;
        }
        
        void set_level(level::level_enum) {}
    };
    
    // Global functions
    inline void set_default_logger(std::shared_ptr<logger>) {}
    inline void set_level(level::level_enum) {}
    inline void set_pattern(const std::string&) {}

    template<typename... Args>
    void info(const std::string& fmt, Args&&... args) {
        std::cout << "[INFO] " << fmt << std::endl; 
    }
    
    template<typename... Args>
    void error(const std::string& fmt, Args&&... args) {
        std::cerr << "[ERROR] " << fmt << std::endl;
    }

    template<typename... Args>
    void critical(const std::string& fmt, Args&&... args) {
        std::cerr << "[CRITICAL] " << fmt << std::endl;
    }
    
    template<typename... Args>
    void warn(const std::string& fmt, Args&&... args) {
        std::cout << "[WARN] " << fmt << std::endl;
    }
    
    template<typename... Args>
    void debug(const std::string& fmt, Args&&... args) {
        #ifdef _DEBUG
        std::cout << "[DEBUG] " << fmt << std::endl;
        #endif
    }

    inline std::shared_ptr<logger> stderr_color_mt(const std::string& name) {
        return std::make_shared<logger>();
    }
}
