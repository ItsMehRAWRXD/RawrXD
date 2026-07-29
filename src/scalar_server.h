#ifndef SCALAR_SERVER_H
#define SCALAR_SERVER_H

<<<<<<< HEAD
class ScalarServer {

public:
    explicit ScalarServer(void* parent = nullptr);
    void start();
    void stop();

private:
    void* m_parent;
};

#endif
=======

// Forward declarations


class TransformerBlockScalar;
class InferenceEngine;

class ScalarServer : public void
{

public:
    explicit ScalarServer(void *parent = nullptr);
    ~ScalarServer();
    
    bool startServer(quint16 port = 8080);
    void stopServer();
    bool loadModel(const std::string &modelPath);
    
    quint16 getPort() const;
    bool isRunning() const;

private:
    void handleNewConnection();
    void handleClientData(void* *clientSocket);

private:
    void handleInferenceRequest(void* *clientSocket, const void* &request);
    void handleChatRequest(void* *clientSocket, const void* &request);
    void handleAnalyzeRequest(void* *clientSocket, const void* &request);
    
    void sendJsonResponse(void* *clientSocket, const void* &response);
    void sendErrorResponse(void* *clientSocket, const std::string &error);
    
    void* *m_server;
    TransformerBlockScalar *m_transformerBlock;
    InferenceEngine *m_inferenceEngine;
};

>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
