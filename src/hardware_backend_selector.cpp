#include "hardware_backend_selector.h"
#include <iostream>

HardwareBackendSelector::HardwareBackendSelector(void* parent)
    : m_parent(parent)
    , m_selectedBackend(Backend::CPU)
    , m_fp16Enabled(false)
    , m_int8Enabled(false)
    , m_memoryPoolMB(1024)
{
}

void HardwareBackendSelector::initialize() {
    detectAvailableBackends();
}

void HardwareBackendSelector::detectAvailableBackends() {
    // Detect CPU
    BackendInfo cpuInfo;
    cpuInfo.backend = Backend::CPU;
    cpuInfo.name = "CPU";
    cpuInfo.available = true;
    m_backends.push_back(cpuInfo);
}

std::vector<HardwareBackendSelector::BackendInfo> HardwareBackendSelector::getAvailableBackends() const {
    return m_backends;
}

void HardwareBackendSelector::selectBackend(Backend backend) {
    m_selectedBackend = backend;
}

HardwareBackendSelector::Backend HardwareBackendSelector::getSelectedBackend() const {
    return m_selectedBackend;
}

void HardwareBackendSelector::setWindowTitle(const std::string& title) {
    (void)title;
}

void HardwareBackendSelector::setMinimumSize(int w, int h) {
    (void)w;
    (void)h;
}

void HardwareBackendSelector::setModal(bool modal) {
    (void)modal;
}
