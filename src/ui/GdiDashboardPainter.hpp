#pragma once
#include <vector>
#include <string>
#include <windows.h>

class GdiDashboardPainter {
private:
    std::vector<int> m_cpuHistory;
    std::vector<int> m_gpuHistory;
    const size_t m_maxHistoryPoints = 120;

    void DrawPlotSpline(HDC hdc, const std::vector<int>& dataPoints, RECT plotArea, COLORREF plotColor);
    void DrawStatusTextMetrics(HDC hdc, RECT textArea, const std::string& label, const std::string& value, COLORREF textColor);

public:
    GdiDashboardPainter();
    void AppendTelemetrySamples(int currentCpuUsage, int currentGpuUsage);
    void PaintDashboardFrame(HWND hwnd, HDC hdc, const std::string& backendName, double tokensPerSec, double buildTime);
};
