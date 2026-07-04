// ============================================================================
// minimal_dap_server.cpp — Standalone DAP Server for Handshake Testing
// ============================================================================
// Minimal implementation that responds to DAP initialize request
// Build: g++ -std=c++20 minimal_dap_server.cpp -o rxd-script-dap.exe
//
// Test:
//   echo Content-Length: 156\r\n\r\n{"seq":1,"type":"request","command":"initialize","arguments":{"clientID":"vscode","adapterID":"rawrxd-script"}} | ./rxd-script-dap.exe
// ============================================================================

#include <iostream>
#include <string>
#include <cstring>

#ifdef _WIN32
#include <windows.h>
#include <io.h>
#include <fcntl.h>
#endif

// Minimal JSON writer
std::string json_escape(const std::string& s) {
    std::string result;
    for (char c : s) {
        switch (c) {
            case '"': result += "\\\""; break;
            case '\\': result += "\\\\"; break;
            case '\b': result += "\\b"; break;
            case '\f': result += "\\f"; break;
            case '\n': result += "\\n"; break;
            case '\r': result += "\\r"; break;
            case '\t': result += "\\t"; break;
            default: result += c;
        }
    }
    return result;
}

void send_dap_response(int request_seq, const std::string& command, 
                       bool success, const std::string& body) {
    static int seq = 1;
    
    std::string response = "{"
        "\"seq\":" + std::to_string(seq++) + ","
        "\"type\":\"response\","
        "\"request_seq\":" + std::to_string(request_seq) + ","
        "\"command\":\"" + command + "\","
        "\"success\":" + std::string(success ? "true" : "false") + ","
        "\"body\":" + body +
    "}";
    
    std::cout << "Content-Length: " << response.length() << "\r\n\r\n" << response;
    std::cout.flush();
}

void send_capabilities(int request_seq) {
    std::string caps = "{"
        "\"supportsConfigurationDoneRequest\":true,"
        "\"supportsEvaluateForHovers\":true,"
        "\"supportsStepBack\":false,"
        "\"supportsRestartRequest\":false,"
        "\"supportsExceptionInfoRequest\":true,"
        "\"supportsSetVariable\":true,"
        "\"supportsRestartFrame\":false"
    "}";
    send_dap_response(request_seq, "initialize", true, caps);
}

void send_empty_response(int request_seq, const std::string& command) {
    send_dap_response(request_seq, command, true, "{}");
}

void send_breakpoints_response(int request_seq) {
    std::string body = "{\"breakpoints\":[]}";
    send_dap_response(request_seq, "setBreakpoints", true, body);
}

void send_stacktrace_response(int request_seq) {
    std::string body = "{"
        "\"stackFrames\":[{"
            "\"id\":1,"
            "\"name\":\"main\","
            "\"source\":{\"path\":\"test.rxs\",\"name\":\"test.rxs\"},"
            "\"line\":1,"
            "\"column\":0"
        "}],"
        "\"totalFrames\":1"
    "}";
    send_dap_response(request_seq, "stackTrace", true, body);
}

void send_variables_response(int request_seq) {
    std::string vars = "[";
    for (int i = 0; i < 16; i++) {
        if (i > 0) vars += ",";
        vars += "{\"name\":\"r" + std::to_string(i) + "\","
                "\"type\":\"register\","
                "\"value\":\"0x" + std::to_string(i * 16) + "\","
                "\"variablesReference\":0}";
    }
    std::string body = "{\"variables\":" + vars + "}";
    send_dap_response(request_seq, "variables", true, body);
}

// Parse simple JSON to extract command
std::string extract_json_field(const std::string& json, const std::string& field) {
    size_t pos = json.find("\"" + field + "\"");
    if (pos == std::string::npos) return "";
    
    pos = json.find(":", pos);
    if (pos == std::string::npos) return "";
    pos++;
    
    // Skip whitespace
    while (pos < json.length() && (json[pos] == ' ' || json[pos] == '\t')) pos++;
    
    if (pos >= json.length()) return "";
    
    if (json[pos] == '"') {
        // String value
        pos++;
        size_t end = json.find("\"", pos);
        if (end == std::string::npos) return "";
        return json.substr(pos, end - pos);
    } else {
        // Number or literal
        size_t end = pos;
        while (end < json.length() && json[end] != ',' && json[end] != '}' && json[end] != ' ') end++;
        return json.substr(pos, end - pos);
    }
}

int main() {
    #ifdef _WIN32
    _setmode(_fileno(stdin), _O_BINARY);
    _setmode(_fileno(stdout), _O_BINARY);
    #endif
    
    std::cerr << "RawrXD-Script DAP Server (Minimal)" << std::endl;
    std::cerr << "Waiting for DAP messages on stdin..." << std::endl;
    
    std::string line;
    while (std::getline(std::cin, line)) {
        // Remove \r if present
        if (!line.empty() && line.back() == '\r') {
            line.pop_back();
        }
        
        // Parse Content-Length header
        if (line.rfind("Content-Length: ", 0) == 0) {
            int contentLength = std::stoi(line.substr(16));
            
            // Read empty line
            std::getline(std::cin, line);
            
            // Read JSON body
            std::string body;
            body.resize(contentLength);
            std::cin.read(&body[0], contentLength);
            
            std::cerr << "Received: " << body << std::endl;
            
            // Parse request
            std::string type = extract_json_field(body, "type");
            std::string command = extract_json_field(body, "command");
            std::string seqStr = extract_json_field(body, "seq");
            int requestSeq = std::stoi(seqStr.empty() ? "0" : seqStr);
            
            std::cerr << "Command: " << command << std::endl;
            
            // Handle commands
            if (command == "initialize") {
                send_capabilities(requestSeq);
            } else if (command == "launch") {
                send_empty_response(requestSeq, "launch");
            } else if (command == "setBreakpoints") {
                send_breakpoints_response(requestSeq);
            } else if (command == "stackTrace") {
                send_stacktrace_response(requestSeq);
            } else if (command == "variables") {
                send_variables_response(requestSeq);
            } else if (command == "configurationDone") {
                send_empty_response(requestSeq, "configurationDone");
            } else if (command == "disconnect") {
                send_empty_response(requestSeq, "disconnect");
                break;
            } else {
                send_empty_response(requestSeq, command);
            }
        }
    }
    
    std::cerr << "DAP Server exiting" << std::endl;
    return 0;
}
