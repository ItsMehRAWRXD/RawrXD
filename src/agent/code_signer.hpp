#pragma once
<<<<<<< HEAD
#include <string>
#include <nlohmann/json.hpp>
#include <functional>
=======

#include <string>
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9

/**
 * @brief Code signing utility for Windows/macOS executables
 */
<<<<<<< HEAD
class CodeSigner {
public:
    static CodeSigner* instance();
    bool signWindowsExecutable(const std::string& exePath,
                              const std::string& certPath = "",
                              const std::string& certPassword = "");
    bool signMacOSBundle(const std::string& bundlePath, const std::string& identity = "");
    bool verifySignature(const std::string& exePath);
    bool notarizeMacOSApp(const std::string& bundlePath,
                         const std::string& appleId,
                         const std::string& password = "");

    // Callbacks (replace Qt signals)
    std::function<void(const std::string&, bool)> onSignatureCompleted;
    std::function<void(const std::string&, bool)> onNotarizationCompleted;

private:
    CodeSigner() = default;
    ~CodeSigner() = default;
    static CodeSigner* s_instance;
    bool executeCommand(const std::string& command, const std::vector<std::string>& args);
=======
class CodeSigner
{
public:
    static CodeSigner* instance();
    
    /**
     * @brief Sign Windows executable with Authenticode
     * @param exePath Path to executable
     * @param certPath Path to PFX certificate (or use cert store)
     * @param certPassword Certificate password (from env: CODE_SIGN_PASSWORD)
     * @return true if signing successful
     */
    bool signWindowsExecutable(const std::string& exePath, 
                              const std::string& certPath = "",
                              const std::string& certPassword = "");
    
    /**
     * @brief Sign macOS application bundle
     * @param bundlePath Path to .app bundle
     * @param identity Developer ID identity (from keychain)
     * @return true if signing successful
     */
    bool signMacOSBundle(const std::string& bundlePath, const std::string& identity = "");
    
    /**
     * @brief Verify executable signature
     * @param exePath Path to executable
     * @return true if signature is valid
     */
    bool verifySignature(const std::string& exePath);
    
private:
    CodeSigner();
    static CodeSigner* s_instance;
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
};
