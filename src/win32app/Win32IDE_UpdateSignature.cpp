#include "Win32IDE.h"
#include "../../include/update_signature.h"
#include <windows.h>
#include <string>

extern "C" void HandleUpdateSignature(void* idePtr) {
    Win32IDE* ide = static_cast<Win32IDE*>(idePtr);
    if (!ide) return;
    wchar_t path[MAX_PATH] = {};
    GetModuleFileNameW(nullptr, path, MAX_PATH);
    auto& verifier = RawrXD::Update::UpdateSignatureVerifier::instance();
    const auto result = verifier.verifyAuthenticode(path);
    std::string msg = result.valid
        ? "[UpdateSignature] Authenticode OK\n"
        : std::string("[UpdateSignature] ") +
              (result.detail ? result.detail : "verify failed") + "\n";
    ide->appendToOutput(msg, "Security",
                        result.valid ? Win32IDE::OutputSeverity::Info
                                     : Win32IDE::OutputSeverity::Warning);
}
