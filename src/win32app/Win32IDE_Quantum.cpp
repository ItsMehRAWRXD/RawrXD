// Win32IDE_Quantum.cpp — Quantization Selector (Batch 5 M02)
#include "Win32IDE.h"
#include <windows.h>
#include <string>

static Win32IDE::QuantizationType g_selectedQuant = Win32IDE::QuantizationType::Q4_K_M;

void Win32IDE::setQuantization(QuantizationType quant) {
    g_selectedQuant = quant;
    std::string name;
    switch (quant) {
        case QuantizationType::Q4_K_M: name = "Q4_K_M"; break;
        case QuantizationType::Q5_K_M: name = "Q5_K_M"; break;
        case QuantizationType::Q8_0: name = "Q8_0"; break;
        case QuantizationType::Q4_0: name = "Q4_0"; break;
        case QuantizationType::Q5_0: name = "Q5_0"; break;
        case QuantizationType::Q6_K: name = "Q6_K"; break;
        default: name = "Unknown"; break;
    }
    appendToOutput("[Quantum] Quantization set to: " + name + "\n", "Output", OutputSeverity::Info);
}

Win32IDE::QuantizationType Win32IDE::getQuantization() const {
    return g_selectedQuant;
}