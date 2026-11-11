// DiagnosticTranslator.h - LSP diagnostic to AnnotationData translation
// Phase II: AgentBridge Integration
// Author: RawrXD Engineering
// Date: 2026-06-23

#pragma once

#include "AnnotationTypes.h"
#include <nlohmann/json.hpp>
#include <string>

namespace RawrXD {
namespace UI {

// Translates LSP diagnostics to AnnotationData
class DiagnosticTranslator {
public:
    // Convert single LSP diagnostic to AnnotationData
    static AnnotationData FromLSPDiagnostic(
        const nlohmann::json& diagnostic,
        int lineNumber
    ) {
        AnnotationData data{};
        data.lineNumber = lineNumber;
        data.source = L"lsp";
        
        // Parse LSP diagnostic fields
        if (diagnostic.contains("range")) {
            auto& range = diagnostic["range"];
            if (range.contains("start") && range.contains("end")) {
                data.columnStart = range["start"]["character"].get<int>() + 1;
                data.columnEnd = range["end"]["character"].get<int>() + 1;
            }
        }
        
        // Convert message
        if (diagnostic.contains("message")) {
            std::string msg = diagnostic["message"].get<std::string>();
            data.message = std::wstring(msg.begin(), msg.end());
        }
        
        // Get severity (default to Error if not specified)
        int severity = 1; // Default to Error
        if (diagnostic.contains("severity")) {
            severity = diagnostic["severity"].get<int>();
        }
        
        // Get code if available
        std::string code;
        if (diagnostic.contains("code")) {
            if (diagnostic["code"].is_string()) {
                code = diagnostic["code"].get<std::string>();
            } else {
                code = std::to_string(diagnostic["code"].get<int>());
            }
        }
        
        // Build tooltip
        std::wstring severityStr;
        switch (severity) {
            case 1: severityStr = L"[Error]"; break;
            case 2: severityStr = L"[Warning]"; break;
            case 3: severityStr = L"[Info]"; break;
            case 4: severityStr = L"[Hint]"; break;
            default: severityStr = L"[Error]"; break;
        }
        
        data.tooltip = severityStr;
        if (!code.empty()) {
            data.tooltip += L" " + std::wstring(code.begin(), code.end());
        }
        data.tooltip += L": " + data.message;
        
        // Map severity and set colors
        switch (severity) {
            case 1: // Error
                data.severity = AnnotationSeverity::Error;
                data.squiggleColor = 0xFF0000FF; // Red (BGRA)
                data.marginColor = 0xFFFF0000;
                break;
            case 2: // Warning
                data.severity = AnnotationSeverity::Warning;
                data.squiggleColor = 0xFF00AAFF; // Orange
                data.marginColor = 0xFF00AA00;
                break;
            case 3: // Information
                data.severity = AnnotationSeverity::Information;
                data.squiggleColor = 0xFFFF8000; // Blue-ish
                data.marginColor = 0xFF0000FF;
                break;
            case 4: // Hint
                data.severity = AnnotationSeverity::Hint;
                data.squiggleColor = 0xFF808080; // Gray
                data.marginColor = 0xFF808080;
                break;
            default:
                data.severity = AnnotationSeverity::Error;
                data.squiggleColor = 0xFF0000FF;
                data.marginColor = 0xFFFF0000;
        }
        
        // Set action
        data.action = AnnotationAction::GoToLine;
        data.actionData = std::to_wstring(lineNumber);
        data.showInMargin = true;
        
        return data;
    }
    
    // Convert LSP publishDiagnostics notification to vector of AnnotationData
    static std::vector<AnnotationData> FromLSPPublishDiagnostics(
        const nlohmann::json& notification
    ) {
        std::vector<AnnotationData> annotations;
        
        if (!notification.contains("params") || 
            !notification["params"].contains("diagnostics")) {
            return annotations;
        }
        
        auto& diagnostics = notification["params"]["diagnostics"];
        if (!diagnostics.is_array()) {
            return annotations;
        }
        
        annotations.reserve(diagnostics.size());
        
        for (const auto& diag : diagnostics) {
            int line = 1; // Default to line 1
            if (diag.contains("range") && 
                diag["range"].contains("start") &&
                diag["range"]["start"].contains("line")) {
                line = diag["range"]["start"]["line"].get<int>() + 1; // LSP is 0-based
            }
            annotations.push_back(FromLSPDiagnostic(diag, line));
        }
        
        return annotations;
    }
    
    // Convert AnnotationData back to LSP format (for round-trip testing)
    static nlohmann::json ToLSPDiagnostic(const AnnotationData& data) {
        nlohmann::json diag;
        
        diag["range"]["start"]["line"] = data.lineNumber - 1;
        diag["range"]["start"]["character"] = data.columnStart - 1;
        diag["range"]["end"]["line"] = data.lineNumber - 1;
        diag["range"]["end"]["character"] = data.columnEnd - 1;
        
        diag["severity"] = static_cast<int>(data.severity);
        
        std::string msg(data.message.begin(), data.message.end());
        diag["message"] = msg;
        
        std::string src(data.source.begin(), data.source.end());
        diag["source"] = src;
        
        return diag;
    }
};

} // namespace UI
} // namespace RawrXD
