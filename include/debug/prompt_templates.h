<<<<<<< HEAD
#ifndef PROMPT_TEMPLATES_H
#define PROMPT_TEMPLATES_H

// C++20, no Qt. Prompt templates for AI debugger. JSON as std::string.

#include <string>

class PromptTemplates
{
public:
    /** Generate a prompt for the AI model based on debug information (JSON string). */
    static std::string generateDebugPrompt(const std::string& debugInfoJson);

private:
    static std::string formatLocals(const std::string& localsJson);
    static std::string formatStack(const std::string& stackJson);
    static std::string formatRegisters(const std::string& registersJson);
};

#endif // PROMPT_TEMPLATES_H
=======
#ifndef PROMPT_TEMPLATES_H
#define PROMPT_TEMPLATES_H

#include <QString>
#include <QJsonObject>
#include <QJsonDocument>

// Prompt templates for AI debugger
class PromptTemplates
{
public:
    // Generate a prompt for the AI model based on debug information
    static QString generateDebugPrompt(const QJsonObject &debugInfo);

private:
    // Helper functions to format different parts of the debug info
    static QString formatLocals(const QJsonArray &locals);
    static QString formatStack(const QJsonArray &stack);
    static QString formatRegisters(const QJsonArray ®isters);
};

#endif // PROMPT_TEMPLATES_H
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
