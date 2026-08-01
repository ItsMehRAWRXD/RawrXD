#include "GdiDashboardPainter.hpp"
#include <sstream>
#include <iomanip>

GdiDashboardPainter::GdiDashboardPainter() {
    m_cpuHistory.assign(m_maxHistoryPoints, 0);
    m_gpuHistory.assign(m_maxHistoryPoints, 0);
}

void GdiDashboardPainter::AppendTelemetrySamples(int currentCpuUsage, int currentGpuUsage) {
    m_cpuHistory.push_back(currentCpuUsage);
    if (m_cpuHistory.size() > m_maxHistoryPoints) m_cpuHistory.erase(m_cpuHistory.begin());

    m_gpuHistory.push_back(currentGpuUsage);
    if (m_gpuHistory.size() > m_maxHistoryPoints) m_gpuHistory.erase(m_gpuHistory.begin());
}

void GdiDashboardPainter::DrawPlotSpline(HDC hdc, const std::vector<int>& dataPoints, RECT plotArea, COLORREF plotColor) {
    HPEN hPen = CreatePen(PS_SOLID, 2, plotColor);
    HPEN hOldPen = (HPEN)SelectObject(hdc, hPen);

    int width = plotArea.right - plotArea.left;
    int height = plotArea.bottom - plotArea.top;
    double stepX = static_cast<double>(width) / (m_maxHistoryPoints - 1);

    for (size_t i = 0; i < dataPoints.size() && i < m_maxHistoryPoints; ++i) {
        int x = plotArea.left + static_cast<int>(i * stepX);
        int y = plotArea.bottom - static_cast<int>((dataPoints[i] / 100.0) * height);

        if (i == 0) {
            MoveToEx(hdc, x, y, NULL);
        } else {
            LineTo(hdc, x, y);
        }
    }

    SelectObject(hdc, hOldPen);
    DeleteObject(hPen);
}

void GdiDashboardPainter::DrawStatusTextMetrics(HDC hdc, RECT textArea, const std::string& label, const std::string& value, COLORREF textColor) {
    SetTextColor(hdc, textColor);
    std::string outputLine = label + ": " + value;
    DrawTextA(hdc, outputLine.c_str(), -1, &textArea, DT_LEFT | DT_VCENTER | DT_SINGLELINE);
}

void GdiDashboardPainter::PaintDashboardFrame(HWND hwnd, HDC hdc, const std::string& backendName, double tokensPerSec, double buildTime) {
    RECT clientRect;
    GetClientRect(hwnd, &clientRect);

    HDC memDC = CreateCompatibleDC(hdc);
    HBITMAP memBitmap = CreateCompatibleBitmap(hdc, clientRect.right, clientRect.bottom);
    HBITMAP oldBitmap = (HBITMAP)SelectObject(memDC, memBitmap);

    HBRUSH bgBrush = CreateSolidBrush(RGB(13, 17, 23));
    FillRect(memDC, &clientRect, bgBrush);
    DeleteObject(bgBrush);

    SetBkMode(memDC, TRANSPARENT);
    HFONT hFont = CreateFontA(14, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE, ANSI_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, "Segoe UI");
    HFONT oldFont = (HFONT)SelectObject(memDC, hFont);

    RECT headerRect = { 16, 16, clientRect.right - 16, 40 };
    SetTextColor(memDC, RGB(88, 166, 255));
    std::string titleStr = "ACTIVE RUNTIME CONTROLS: " + backendName;
    DrawTextA(memDC, titleStr.c_str(), -1, &headerRect, DT_LEFT | DT_TOP | DT_SINGLELINE);

    std::ostringstream tokStream, buildStream;
    tokStream << std::fixed << std::setprecision(1) << tokensPerSec;
    buildStream << std::fixed << std::setprecision(2) << buildTime;

    RECT tokRect = { 16, 50, 200, 70 };
    DrawStatusTextMetrics(memDC, tokRect, "Tokens/sec", tokStream.str(), RGB(0, 255, 128));

    RECT buildRect = { 16, 75, 200, 95 };
    DrawStatusTextMetrics(memDC, buildRect, "Build Time", buildStream.str() + "s", RGB(255, 165, 0));

    RECT cpuPlot = { 16, 110, clientRect.right / 2 - 8, clientRect.bottom - 16 };
    RECT gpuPlot = { clientRect.right / 2 + 8, 110, clientRect.right - 16, clientRect.bottom - 16 };

    HPEN gridPen = CreatePen(PS_DOT, 1, RGB(40, 44, 52));
    HPEN oldPen = (HPEN)SelectObject(memDC, gridPen);
    for (int y = cpuPlot.top; y < cpuPlot.bottom; y += 30) {
        MoveToEx(memDC, cpuPlot.left, y, NULL);
        LineTo(memDC, cpuPlot.right, y);
        MoveToEx(memDC, gpuPlot.left, y, NULL);
        LineTo(memDC, gpuPlot.right, y);
    }
    SelectObject(memDC, oldPen);
    DeleteObject(gridPen);

    DrawPlotSpline(memDC, m_cpuHistory, cpuPlot, RGB(88, 166, 255));
    DrawPlotSpline(memDC, m_gpuHistory, gpuPlot, RGB(255, 107, 107));

    RECT cpuLabel = { cpuPlot.left, cpuPlot.top - 20, cpuPlot.right, cpuPlot.top };
    DrawStatusTextMetrics(memDC, cpuLabel, "CPU Load", "", RGB(88, 166, 255));

    RECT gpuLabel = { gpuPlot.left, gpuPlot.top - 20, gpuPlot.right, gpuPlot.top };
    DrawStatusTextMetrics(memDC, gpuLabel, "GPU Load", "", RGB(255, 107, 107));

    SelectObject(memDC, oldFont);
    DeleteObject(hFont);

    BitBlt(hdc, 0, 0, clientRect.right, clientRect.bottom, memDC, 0, 0, SRCCOPY);

    SelectObject(memDC, oldBitmap);
    DeleteObject(memBitmap);
    DeleteDC(memDC);
}
