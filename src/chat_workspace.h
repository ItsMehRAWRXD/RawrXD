#pragma once
#include <string>

class ChatWorkspace {

public:
    explicit ChatWorkspace(void* parent = nullptr);
    void initialize();
    void commandIssued(const std::string& command);

private:
    void* m_parent;
};

