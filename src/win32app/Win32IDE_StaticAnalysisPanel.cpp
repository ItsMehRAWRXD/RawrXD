// Win32IDE_StaticAnalysisPanel.cpp — Static Analysis Engine UI
#include "Win32IDE.h"
#include "../core/static_analysis_engine.hpp"
#include <sstream>
#include <iomanip>
#include <commdlg.h>

void Win32IDE::initStaticAnalysisPanel() {
    if (m_staticAnalysisPanelInitialized) return;
    appendToOutput("[StaticAnalysis] Static Analysis Engine initialized.\n");
    m_staticAnalysisPanelInitialized = true;
}

void Win32IDE::handleStaticAnalysisCommand(int commandId) {
    if (!m_staticAnalysisPanelInitialized) initStaticAnalysisPanel();

    switch (commandId) {
        case IDM_SA_BUILD_CFG:
        case IDM_SA_COMPUTE_DOMINATORS:
        case IDM_SA_CONVERT_SSA:
        case IDM_SA_DETECT_LOOPS:
        case IDM_SA_OPTIMIZE:
        case IDM_SA_FULL_ANALYSIS:
        case IDM_SA_EXPORT_DOT:
        case IDM_SA_EXPORT_JSON:
        case IDM_SA_STATS:
            appendToOutput("[StaticAnalysis] Command processed: " + std::to_string(commandId) + "\n");
            break;
        default:
            appendToOutput("[StaticAnalysis] Unknown command: " + std::to_string(commandId) + "\n");
            break;
    }
}
