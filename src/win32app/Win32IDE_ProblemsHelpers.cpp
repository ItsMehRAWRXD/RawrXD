#include "Win32IDE.h"
void Win32IDE::refreshProblemsView()
{
    if (m_hwndProblemsListView) {
        updatePanelContent();
        updateEnhancedStatusBar();
    }
}
