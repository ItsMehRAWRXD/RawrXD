#pragma once
#include <string>

namespace RawrXD::IdeAuth {

void SetListenPort(int port);
void SetWorkspaceRoot(const std::string& root);
const char* SessionToken();
bool PrivilegedExecGranted();
std::string HeaderField(const std::string& headers, const char* key);

bool OriginAllowed(const std::string& origin);
bool HeaderHasSession(const std::string& headers);
void NoteResponseOrigin(const std::string& origin);
const char* ResponseAllowOrigin();
std::string CorsHeaderLines();

enum class HttpDecision { Allow, Unauthorized, ForbiddenOrigin, ExecDenied };

HttpDecision DecideWin32(const std::string& method, const std::string& path,
                         const std::string& headers, const std::string& body);

bool CanonicalInsideWorkspace(const std::string& input, std::string& canonical,
                              std::string& error);
bool ExtensionHashTrusted(const std::string& packagePath, std::string& error);

}
