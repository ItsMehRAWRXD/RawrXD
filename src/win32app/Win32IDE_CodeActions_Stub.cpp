// File deleted - stub no longer needed

using json = nlohmann::json;

// ============================================================================
// Code Actions - Stub Implementations
// ============================================================================

namespace Win32IDE_CodeActions {

    json lspCodeActions(const std::string& fileUri, int line, int column) {
        (void)fileUri; (void)line; (void)column;
        // Stub - returns empty code actions
        return json::array();
    }

    bool applyCodeAction(const json& action) {
        (void)action;
        // Stub - returns false (not applied)
        return false;
    }

    bool applyTextEdit(const json& edit) {
        (void)edit;
        // Stub - returns false (not applied)
        return false;
    }

    void cmdFixAllDiagnostics() {
        // Stub - will be implemented with actual diagnostic fixing
    }

    void cmdOrganizeImports() {
        // Stub - will be implemented with actual import organization
    }

    void showCodeActions(int line, int column) {
        (void)line; (void)column;
        // Stub - will be implemented with actual UI
    }

    void executeLSPCommand(const std::string& command, const json& arguments) {
        (void)command; (void)arguments;
        // Stub - will be implemented with actual LSP command execution
    }

}  // namespace Win32IDE_CodeActions
