// BeaconDAPServer.cpp
// Phase 25: DAP Server Entry Point
// ============================================================================
// Standalone DAP server that wraps BeaconDebugger backend
// Usage: BeaconDAPServer.exe --stdio
// ============================================================================

#include <windows.h>
#include <iostream>
#include <string>
#include <vector>
#include <sstream>
#include <memory>
#include <fstream>

// Include DAP components
#include "DAPTransport.h"
#include "DAPAdapter.h"
#include "Debugger_Backend.h"

// CRITICAL: Set binary mode for stdin/stdout on Windows
// This prevents CRLF translation which breaks Content-Length framing
#ifdef _WIN32
#include <io.h>
#include <fcntl.h>
#endif

using namespace RawrXD;

// ============================================================================
// Command Line Parsing
// ============================================================================
struct ServerConfig {
    bool useStdio = true;           // Use stdin/stdout for DAP
    bool useSocket = false;         // Use TCP socket (future)
    uint16_t port = 4711;           // TCP port (future)
    bool verbose = false;           // Verbose logging
    std::string logFile;            // Optional log file
};

bool ParseCommandLine(int argc, char* argv[], ServerConfig& config) {
    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        
        if (arg == "--stdio" || arg == "-s") {
            config.useStdio = true;
            config.useSocket = false;
        } else if (arg == "--socket" || arg == "-p") {
            config.useSocket = true;
            config.useStdio = false;
            if (i + 1 < argc) {
                config.port = static_cast<uint16_t>(std::stoi(argv[++i]));
            }
        } else if (arg == "--verbose" || arg == "-v") {
            config.verbose = true;
        } else if (arg == "--log" || arg == "-l") {
            if (i + 1 < argc) {
                config.logFile = argv[++i];
            }
        } else if (arg == "--help" || arg == "-h") {
            std::cout << "BeaconDAPServer - RawrXD DAP Server\n"
                      << "Usage: BeaconDAPServer [options]\n"
                      << "\nOptions:\n"
                      << "  --stdio, -s       Use stdin/stdout for DAP (default)\n"
                      << "  --socket PORT     Use TCP socket (future)\n"
                      << "  --verbose, -v     Enable verbose logging\n"
                      << "  --log FILE        Write log to file\n"
                      << "  --help, -h        Show this help\n";
            return false;
        }
    }
    return true;
}

// ============================================================================
// Logging
// ============================================================================
class Logger {
public:
    void Initialize(const std::string& logFile) {
        if (!logFile.empty()) {
            logStream_.open(logFile, std::ios::app);
        }
    }
    
    void Log(const std::string& message) {
        std::string timestamp = GetTimestamp();
        std::string fullMessage = "[" + timestamp + "] " + message;
        
        // Write to stderr (not stdout - that's for DAP)
        std::cerr << fullMessage << std::endl;
        
        // Write to log file if open
        if (logStream_.is_open()) {
            logStream_ << fullMessage << std::endl;
            logStream_.flush();
        }
    }
    
private:
    std::ofstream logStream_;
    
    std::string GetTimestamp() {
        SYSTEMTIME st;
        GetLocalTime(&st);
        char buffer[64];
        sprintf_s(buffer, "%04d-%02d-%02d %02d:%02d:%02d.%03d",
                  st.wYear, st.wMonth, st.wDay,
                  st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
        return buffer;
    }
};

static Logger g_logger;

// ============================================================================
// Main Entry Point
// ============================================================================
int main(int argc, char* argv[]) {
    // CRITICAL: Set binary mode BEFORE any I/O operations
    // This prevents Windows from translating LF to CRLF
    #ifdef _WIN32
    _setmode(_fileno(stdin), _O_BINARY);
    _setmode(_fileno(stdout), _O_BINARY);
    #endif
    
    ServerConfig config;
    
    if (!ParseCommandLine(argc, argv, config)) {
        return 0;
    }
    
    // Initialize logging
    g_logger.Initialize(config.logFile);
    g_logger.Log("BeaconDAPServer starting...");
    g_logger.Log("Binary mode set for stdin/stdout");
    
    // Set console mode for binary I/O
    HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE);
    HANDLE hStdout = GetStdHandle(STD_OUTPUT_HANDLE);
    
    DWORD mode;
    GetConsoleMode(hStdin, &mode);
    SetConsoleMode(hStdin, mode & ~(ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT));
    
    // Create transport
    DAP::DAPTransport transport;
    DAP::DAPTransportConfig transportConfig{};
    transportConfig.hInput = hStdin;
    transportConfig.hOutput = hStdout;
    if (!transport.Initialize(transportConfig)) {
        g_logger.Log("Failed to initialize DAP transport");
        return 1;
    }
    g_logger.Log("DAP transport initialized");
    
    // Create debug session
    auto debugSession = std::make_unique<Debugger::DebugSession>();
    if (!debugSession->Initialize()) {
        g_logger.Log("Failed to initialize debug session");
        return 1;
    }
    g_logger.Log("Debug session initialized");
    
    // Initialize DAP adapter
    if (!InitializeDAPAdapter(&transport, debugSession.get())) {
        g_logger.Log("Failed to initialize DAP adapter");
        return 1;
    }
    g_logger.Log("DAP adapter initialized");
    
    // Run the DAP adapter
    auto* adapter = DAP::GetDAPAdapter();
    if (adapter) {
        g_logger.Log("DAP server running - waiting for client...");
        adapter->Run();
    }
    
    // Cleanup
    g_logger.Log("Shutting down...");
    DAP::ShutdownDAPAdapter();
    debugSession->Shutdown();
    
    g_logger.Log("BeaconDAPServer exited");
    return 0;
}
