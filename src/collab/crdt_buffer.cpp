<<<<<<< HEAD
#include "collab/crdt_buffer.h"
#include <sstream>

void CRDTBuffer::applyRemoteOperation(const std::string &operationJson)
{
    // Parse JSON operation
    // Format: {"type":"INSERT","position":10,"text":"hello"}
    try {
        std::istringstream iss(operationJson);
        std::string token;
        std::string type;
        int position = 0;
        std::string text;
        int length = 0;

        // Simple JSON parsing
        std::getline(iss, token, ':'); // Skip "type"
        std::getline(iss, token, ',');
        if (token.find("INSERT") != std::string::npos) {
            type = "INSERT";
        } else if (token.find("DELETE") != std::string::npos) {
            type = "DELETE";
        }

        // Parse position
        std::getline(iss, token, ':'); // Skip "position"
        std::getline(iss, token, ',');
        position = std::stoi(token);

        if (type == "INSERT") {
            // Parse text
            std::getline(iss, token, ':'); // Skip "text"
            std::getline(iss, token, '"');
            std::getline(iss, text, '"');
            if (position >= 0 && position <= (int)m_text.length()) {
                m_text.insert(position, text);
            }
        } else if (type == "DELETE") {
            // Parse length
            std::getline(iss, token, ':'); // Skip "length"
            std::getline(iss, token, ',');
            length = std::stoi(token);
            if (position >= 0 && position < (int)m_text.length() && length > 0) {
                int deleteLength = std::min(length, (int)m_text.length() - position);
                m_text.erase(position, deleteLength);
            }
        }

        if (m_onTextChanged) {
            m_onTextChanged(m_text);
        }
    } catch (const std::exception&) {
        // Invalid operation format
    }
=======
#include "crdt_buffer.h"

CRDTBuffer::CRDTBuffer()
    
{
}

void CRDTBuffer::applyRemoteOperation(const std::string &operation)
{
    // In a real implementation, this would parse the operation and apply it to the text
    // For now, we'll just print a message
    // textChanged signal if the text was actually changed
    // textChanged(m_text);
}

std::string CRDTBuffer::getText() const
{
    return m_text;
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
}

void CRDTBuffer::insertText(int position, const std::string &text)
{
<<<<<<< HEAD
    if (position < 0 || position > (int)m_text.length() || text.empty()) {
        return;
    }

    m_text.insert(position, text);

    if (m_onTextChanged) {
        m_onTextChanged(m_text);
    }

    if (m_onOperationGenerated) {
        std::ostringstream oss;
        oss << "{\"type\":\"INSERT\",\"position\":" << position
            << ",\"text\":\"" << text << "\"}";
        m_onOperationGenerated(oss.str());
    }
=======
    if (position < 0 || position > m_text.length()) {
        return;
    }
    m_text.insert(position, text);
    textChanged(m_text);
    // In a real implementation, this would generate an operation and operationGenerated
    // operationGenerated(operation);
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
}

void CRDTBuffer::deleteText(int position, int length)
{
<<<<<<< HEAD
    if (position < 0 || position >= (int)m_text.length() || length <= 0) {
        return;
    }

    int actualLength = std::min(length, (int)m_text.length() - position);
    m_text.erase(position, actualLength);

    if (m_onTextChanged) {
        m_onTextChanged(m_text);
    }

    if (m_onOperationGenerated) {
        std::ostringstream oss;
        oss << "{\"type\":\"DELETE\",\"position\":" << position
            << ",\"length\":" << actualLength << "}";
        m_onOperationGenerated(oss.str());
    }
=======
    if (position < 0 || position >= m_text.length() || length <= 0) {
        return;
    }
    m_text.remove(position, length);
    textChanged(m_text);
    // In a real implementation, this would generate an operation and operationGenerated
    // operationGenerated(operation);
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
}

