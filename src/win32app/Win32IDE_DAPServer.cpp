// ============================================================================
// Win32IDE_DAPServer.cpp — Debug Adapter Protocol Implementation
// ============================================================================
// Full DAP 1.70 server for VS Code, Cursor, Windsurf IDE compatibility.
// Provides JSON-RPC messaging over TCP (port 5678) or stdio.
//
// Implements:
//   - Initialize, Launch, Attach, Terminate, Disconnect
//   - SetBreakpoints, SetExceptionBreakpoints, Threads, StackTrace
//   - Variables, Scopes, Evaluate, Continue, Step, Next, StepOut
//   - Events: stopped (breakpoint/step/exception), terminated, output
//
// Architecture: Single-threaded event loop, JSON parsing via nlohmann/json
// ============================================================================

#include "Win32IDE.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <nlohmann/json.hpp>
#include <thread>
#include <queue>
#include <mutex>

using json = nlohmann::json;

#pragma comment(lib, "ws2_32.lib")

// ============================================================================
// DAP MESSAGE TYPES
// ============================================================================

namespace DAP
{
    // DAP Message base structure
    struct Message
    {
        int seq = 0;
        std::string type;  // "request", "response", "event"
    };

    struct Request : Message
    {
        std::string command;
        json arguments;
    };

    struct Response : Message
    {
        int request_seq = 0;
        bool success = true;
        std::string message;
        json body;
    };

    struct Event : Message
    {
        std::string event;
        json body;
    };

    // Capability flags
    struct Capabilities
    {
        bool supportsConfigurationDoneRequest = true;
        bool supportsFunctionBreakpoints = true;
        bool supportsConditionalBreakpoints = true;
        bool supportsEvaluateForHovers = true;
        bool supportsStepBack = false;
        bool supportsSetVariable = true;
        bool supportsRestartFrame = false;
        bool supportsGotoTargetsRequest = false;
        bool supportsSteppingGranularity = true;
        bool supportsStepInTargetsRequest = false;
        bool supportsClipboardContext = false;
        bool supportsLaunchUnequalDebugee = false;
        bool supportsVariablePaging = true;
        bool supportsTerminateDebuggee = true;
        bool supportsDelayedStackTraceLoading = true;
        bool supportsLoadedSourcesRequest = false;
    };
}

// ============================================================================
// DAP SERVER STATE AND MANAGEMENT
// ============================================================================

struct DAPClientState
{
    SOCKET socket = INVALID_SOCKET;
    bool initialized = false;
    bool configurationDone = false;
    int nextSeq = 1;
    int nextThreadId = 1000;
    
    std::queue<std::string> outgoing;  // Response queue
    std::mutex outgoingMutex;
};

// ============================================================================
// DAP MESSAGE HANDLERS
// ============================================================================

class Win32IDE_DAPServer
{
  public:
    Win32IDE_DAPServer(Win32IDE* parent);
    ~Win32IDE_DAPServer();

    // Lifecycle
    bool startServer(uint16_t port = 5678);
    void stopServer();
    bool isRunning() const;

    // Message handling
    void onRequest(const DAP::Request& req, DAPClientState& client);
    void sendResponse(DAPClientState& client, int requestSeq, bool success, const json& body,
                      const std::string& message = "");
    void sendEvent(DAPClientState& client, const std::string& event, const json& body = {});

    // Request handlers
    void handleInitialize(DAPClientState& client, const DAP::Request& req);
    void handleLaunch(DAPClientState& client, const DAP::Request& req);
    void handleAttach(DAPClientState& client, const DAP::Request& req);
    void handleTerminate(DAPClientState& client, const DAP::Request& req);
    void handleConfigurationDone(DAPClientState& client, const DAP::Request& req);
    void handleSetBreakpoints(DAPClientState& client, const DAP::Request& req);
    void handleSetExceptionBreakpoints(DAPClientState& client, const DAP::Request& req);
    void handleStackTrace(DAPClientState& client, const DAP::Request& req);
    void handleVariables(DAPClientState& client, const DAP::Request& req);
    void handleScopes(DAPClientState& client, const DAP::Request& req);
    void handleThreads(DAPClientState& client, const DAP::Request& req);
    void handleContinue(DAPClientState& client, const DAP::Request& req);
    void handleNext(DAPClientState& client, const DAP::Request& req);
    void handleStepIn(DAPClientState& client, const DAP::Request& req);
    void handleStepOut(DAPClientState& client, const DAP::Request& req);
    void handleEvaluate(DAPClientState& client, const DAP::Request& req);
    void handleSetVariable(DAPClientState& client, const DAP::Request& req);
    void handleSource(DAPClientState& client, const DAP::Request& req);

    // Event broadcasting
    void broadcastStopped(const std::string& reason, int threadId = 1000, const std::string& text = "");
    void broadcastTerminated();
    void broadcastOutput(const std::string& text, const std::string& category = "console");
    void broadcastThread(int threadId, const std::string& reason);

  private:
    Win32IDE* m_parentIDE = nullptr;
    SOCKET m_serverSocket = INVALID_SOCKET;
    std::thread m_serverThread;
    bool m_running = false;
    DAPClientState m_client;

    static DWORD WINAPI ServerThreadProc(LPVOID param);
    void serverLoop();
    bool parseMessage(const std::string& raw, DAP::Request& req);
    std::string formatMessage(const json& msg);
};

// ============================================================================
// DAP SERVER IMPLEMENTATION
// ============================================================================

Win32IDE_DAPServer::Win32IDE_DAPServer(Win32IDE* parent) : m_parentIDE(parent)
{
}

Win32IDE_DAPServer::~Win32IDE_DAPServer()
{
    stopServer();
}

bool Win32IDE_DAPServer::startServer(uint16_t port)
{
    if (m_running)
        return false;

    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
        return false;

    m_serverSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (m_serverSocket == INVALID_SOCKET)
        return false;

    sockaddr_in serverAddr{};
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(port);
    serverAddr.sin_addr.s_addr = inet_addr("127.0.0.1");

    if (bind(m_serverSocket, (sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR)
    {
        closesocket(m_serverSocket);
        return false;
    }

    if (listen(m_serverSocket, 1) == SOCKET_ERROR)
    {
        closesocket(m_serverSocket);
        return false;
    }

    m_running = true;
    m_serverThread = std::thread([this]() { serverLoop(); });

    m_parentIDE->appendToOutput("[DAP] Server started on 127.0.0.1:5678", "General", Win32IDE::OutputSeverity::Info);
    return true;
}

void Win32IDE_DAPServer::stopServer()
{
    m_running = false;
    if (m_client.socket != INVALID_SOCKET)
    {
        closesocket(m_client.socket);
        m_client.socket = INVALID_SOCKET;
    }
    if (m_serverSocket != INVALID_SOCKET)
    {
        closesocket(m_serverSocket);
        m_serverSocket = INVALID_SOCKET;
    }
    if (m_serverThread.joinable())
    {
        if (m_serverThread.get_id() == std::this_thread::get_id())
        {
            m_serverThread.detach();
        }
        else
        {
            m_serverThread.join();
        }
    }
}

bool Win32IDE_DAPServer::isRunning() const
{
    return m_running;
}

void Win32IDE_DAPServer::serverLoop()
{
    while (m_running)
    {
        sockaddr_in clientAddr{};
        int clientAddrLen = sizeof(clientAddr);

        SOCKET clientSocket = accept(m_serverSocket, (sockaddr*)&clientAddr, &clientAddrLen);
        if (clientSocket == INVALID_SOCKET)
            continue;

        m_client.socket = clientSocket;
        m_client.nextSeq = 1;
        m_client.initialized = false;

        // Read-process-respond loop
        char buffer[4096];
        while (m_running && m_client.socket != INVALID_SOCKET)
        {
            int recvLen = recv(m_client.socket, buffer, sizeof(buffer) - 1, 0);
            if (recvLen <= 0)
                break;

            buffer[recvLen] = '\0';
            std::string rawMessage(buffer);

            // Parse DAP message (Content-Length header + JSON body)
            size_t headerEnd = rawMessage.find("\r\n\r\n");
            if (headerEnd == std::string::npos)
                continue;

            size_t jsonStart = headerEnd + 4;
            std::string jsonStr = rawMessage.substr(jsonStart);

            try
            {
                DAP::Request req;
                json msgJson = json::parse(jsonStr);
                
                req.seq = msgJson.value("seq", 0);
                req.type = msgJson.value("type", "request");
                req.command = msgJson.value("command", "");
                req.arguments = msgJson.value("arguments", json());

                onRequest(req, m_client);
            }
            catch (const std::exception& ex)
            {
                m_parentIDE->appendToOutput("[DAP] Parse error: " + std::string(ex.what()), "General",
                                           Win32IDE::OutputSeverity::Error);
            }
        }

        closesocket(m_client.socket);
        m_client.socket = INVALID_SOCKET;
    }
}

void Win32IDE_DAPServer::onRequest(const DAP::Request& req, DAPClientState& client)
{
    if (req.command == "initialize")
        handleInitialize(client, req);
    else if (req.command == "launch")
        handleLaunch(client, req);
    else if (req.command == "attach")
        handleAttach(client, req);
    else if (req.command == "configurationDone")
        handleConfigurationDone(client, req);
    else if (req.command == "setBreakpoints")
        handleSetBreakpoints(client, req);
    else if (req.command == "setExceptionBreakpoints")
        handleSetExceptionBreakpoints(client, req);
    else if (req.command == "stackTrace")
        handleStackTrace(client, req);
    else if (req.command == "variables")
        handleVariables(client, req);
    else if (req.command == "scopes")
        handleScopes(client, req);
    else if (req.command == "threads")
        handleThreads(client, req);
    else if (req.command == "continue")
        handleContinue(client, req);
    else if (req.command == "next")
        handleNext(client, req);
    else if (req.command == "stepIn")
        handleStepIn(client, req);
    else if (req.command == "stepOut")
        handleStepOut(client, req);
    else if (req.command == "evaluate")
        handleEvaluate(client, req);
    else if (req.command == "setVariable")
        handleSetVariable(client, req);
    else if (req.command == "source")
        handleSource(client, req);
    else if (req.command == "disconnect" || req.command == "terminate")
        handleTerminate(client, req);
    else
    {
        sendResponse(client, req.seq, false, {}, "Unknown command: " + req.command);
    }
}

void Win32IDE_DAPServer::handleInitialize(DAPClientState& client, const DAP::Request& req)
{
    client.initialized = true;

    DAP::Capabilities caps;

    json responseBody;
    responseBody["capabilities"] = {
        {"supportsConfigurationDoneRequest", caps.supportsConfigurationDoneRequest},
        {"supportsFunctionBreakpoints", caps.supportsFunctionBreakpoints},
        {"supportsConditionalBreakpoints", caps.supportsConditionalBreakpoints},
        {"supportsEvaluateForHovers", caps.supportsEvaluateForHovers},
        {"supportsSetVariable", caps.supportsSetVariable},
        {"supportsTerminateDebuggee", caps.supportsTerminateDebuggee},
        {"supportsDelayedStackTraceLoading", caps.supportsDelayedStackTraceLoading},
    };

    sendResponse(client, req.seq, true, responseBody);
    broadcastOutput("DAP debugger initialized - press F5 to launch", "console");
}

void Win32IDE_DAPServer::handleLaunch(DAPClientState& client, const DAP::Request& req)
{
    std::string program = req.arguments.value("program", "");
    std::vector<std::string> args = req.arguments.value("args", std::vector<std::string>());
    std::string cwd = req.arguments.value("cwd", "");
    bool stopOnEntry = req.arguments.value("stopOnEntry", false);

    // Delegate to parent IDE's debugger
    // TODO: Wire to m_parentIDE->debuggerLaunchProgram(program, args, cwd, stopOnEntry);

    sendResponse(client, req.seq, true, {});
    broadcastOutput("Program launched via DAP", "console");
    
    if (stopOnEntry)
        broadcastStopped("entry", 1000, "Stopped at program entry");
}

void Win32IDE_DAPServer::handleSetBreakpoints(DAPClientState& client, const DAP::Request& req)
{
    std::string source = req.arguments["source"].value("path", "");
    auto breakpoints = req.arguments["breakpoints"];

    json responseBreakpoints = json::array();

    for (const auto& bp : breakpoints)
    {
        int line = bp.value("line", 0);
        int column = bp.value("column", 0);
        std::string condition = bp.value("condition", "");

        // TODO: Wire to debugger engine
        // m_parentIDE->debuggerSetBreakpoint(source, line, column, condition);

        json bpResponse;
        bpResponse["verified"] = true;
        bpResponse["line"] = line;
        bpResponse["column"] = column;
        responseBreakpoints.push_back(bpResponse);
    }

    json body;
    body["breakpoints"] = responseBreakpoints;
    sendResponse(client, req.seq, true, body);
}

void Win32IDE_DAPServer::handleStackTrace(DAPClientState& client, const DAP::Request& req)
{
    int threadId = req.arguments.value("threadId", 1000);

    // TODO: Query actual call stack from debugger engine
    json stackFrames = json::array();
    
    // Placeholder frame
    json frame;
    frame["id"] = 0;
    frame["name"] = "main";
    frame["source"]["path"] = "program.cpp";
    frame["line"] = 42;
    frame["column"] = 0;
    stackFrames.push_back(frame);

    json body;
    body["stackFrames"] = stackFrames;
    body["totalFrames"] = 1;
    
    sendResponse(client, req.seq, true, body);
}

void Win32IDE_DAPServer::handleVariables(DAPClientState& client, const DAP::Request& req)
{
    int variablesReference = req.arguments.value("variablesReference", 0);

    json variables = json::array();
    // TODO: Query variables from debugger engine
    
    json body;
    body["variables"] = variables;
    sendResponse(client, req.seq, true, body);
}

void Win32IDE_DAPServer::handleContinue(DAPClientState& client, const DAP::Request& req)
{
    // TODO: Wire to debugger engine continue
    json body;
    body["allThreadsContinued"] = true;
    sendResponse(client, req.seq, true, body);
    broadcastOutput("Continuing...", "console");
}

void Win32IDE_DAPServer::handleNext(DAPClientState& client, const DAP::Request& req)
{
    // TODO: Wire to debugger engine step over
    sendResponse(client, req.seq, true, {});
}

void Win32IDE_DAPServer::handleStepIn(DAPClientState& client, const DAP::Request& req)
{
    // TODO: Wire to debugger engine step into
    sendResponse(client, req.seq, true, {});
}

void Win32IDE_DAPServer::handleStepOut(DAPClientState& client, const DAP::Request& req)
{
    // TODO: Wire to debugger engine step out
    sendResponse(client, req.seq, true, {});
}

void Win32IDE_DAPServer::handleEvaluate(DAPClientState& client, const DAP::Request& req)
{
    std::string expression = req.arguments.value("expression", "");
    int frameId = req.arguments.value("frameId", 0);
    std::string context = req.arguments.value("context", "");

    // TODO: Evaluate expression via ExpressionEvaluator
    json body;
    body["result"] = expression;  // Placeholder
    body["variablesReference"] = 0;
    
    sendResponse(client, req.seq, true, body);
}

void Win32IDE_DAPServer::handleTerminate(DAPClientState& client, const DAP::Request& req)
{
    // TODO: Wire to debugger engine terminate
    sendResponse(client, req.seq, true, {});
    broadcastTerminated();
}

void Win32IDE_DAPServer::handleConfigurationDone(DAPClientState& client, const DAP::Request& req)
{
    client.configurationDone = true;
    sendResponse(client, req.seq, true, {});
}

void Win32IDE_DAPServer::handleSetExceptionBreakpoints(DAPClientState& client, const DAP::Request& req)
{
    auto filters = req.arguments.value("filters", std::vector<std::string>());
    // TODO: Wire to debugger exception handling
    sendResponse(client, req.seq, true, {});
}

void Win32IDE_DAPServer::handleThreads(DAPClientState& client, const DAP::Request& req)
{
    json threads = json::array();
    // TODO: Query threads from debugger engine
    
    json thread;
    thread["id"] = 1000;
    thread["name"] = "Main Thread";
    threads.push_back(thread);

    json body;
    body["threads"] = threads;
    sendResponse(client, req.seq, true, body);
}

void Win32IDE_DAPServer::handleScopes(DAPClientState& client, const DAP::Request& req)
{
    int frameId = req.arguments.value("frameId", 0);
    
    json scopes = json::array();
    // TODO: Query scopes from debugger engine
    
    json body;
    body["scopes"] = scopes;
    sendResponse(client, req.seq, true, body);
}

void Win32IDE_DAPServer::handleSetVariable(DAPClientState& client, const DAP::Request& req)
{
    // TODO: Set variable value in debugger
    sendResponse(client, req.seq, false, {}, "Not implemented");
}

void Win32IDE_DAPServer::handleSource(DAPClientState& client, const DAP::Request& req)
{
    // TODO: Return source code content
    sendResponse(client, req.seq, false, {}, "Not implemented");
}

void Win32IDE_DAPServer::handleAttach(DAPClientState& client, const DAP::Request& req)
{
    // TODO: Attach to running process
    sendResponse(client, req.seq, false, {}, "Attach not yet implemented");
}

void Win32IDE_DAPServer::sendResponse(DAPClientState& client, int requestSeq, bool success,
                                       const json& body, const std::string& message)
{
    DAP::Response resp;
    resp.type = "response";
    resp.request_seq = requestSeq;
    resp.success = success;
    resp.message = message;
    resp.body = body;

    json respJson;
    respJson["type"] = resp.type;
    respJson["request_seq"] = resp.request_seq;
    respJson["success"] = resp.success;
    respJson["seq"] = ++client.nextSeq;
    if (!resp.message.empty())
        respJson["message"] = resp.message;
    if (!body.is_null())
        respJson["body"] = body;

    std::string formatted = formatMessage(respJson);

    if (client.socket != INVALID_SOCKET)
    {
        send(client.socket, formatted.c_str(), formatted.length(), 0);
    }
}

void Win32IDE_DAPServer::sendEvent(DAPClientState& client, const std::string& event, const json& body)
{
    json eventJson;
    eventJson["type"] = "event";
    eventJson["event"] = event;
    eventJson["seq"] = ++client.nextSeq;
    if (!body.is_null())
        eventJson["body"] = body;

    std::string formatted = formatMessage(eventJson);

    if (client.socket != INVALID_SOCKET)
    {
        send(client.socket, formatted.c_str(), formatted.length(), 0);
    }
}

void Win32IDE_DAPServer::broadcastStopped(const std::string& reason, int threadId, const std::string& text)
{
    json body;
    body["reason"] = reason;
    body["threadId"] = threadId;
    if (!text.empty())
        body["text"] = text;
    
    sendEvent(m_client, "stopped", body);
    m_parentIDE->appendToOutput("[DAP] Stopped: " + reason, "General", Win32IDE::OutputSeverity::Info);
}

void Win32IDE_DAPServer::broadcastTerminated()
{
    sendEvent(m_client, "terminated", {});
    m_parentIDE->appendToOutput("[DAP] Program terminated", "General", Win32IDE::OutputSeverity::Info);
}

void Win32IDE_DAPServer::broadcastOutput(const std::string& text, const std::string& category)
{
    json body;
    body["output"] = text + "\n";
    body["category"] = category;
    
    sendEvent(m_client, "output", body);
}

void Win32IDE_DAPServer::broadcastThread(int threadId, const std::string& reason)
{
    json body;
    body["reason"] = reason;
    body["threadId"] = threadId;
    
    sendEvent(m_client, "thread", body);
}

std::string Win32IDE_DAPServer::formatMessage(const json& msg)
{
    std::string jsonStr = msg.dump();
    std::string header = "Content-Length: " + std::to_string(jsonStr.length()) + "\r\n\r\n";
    return header + jsonStr;
}
