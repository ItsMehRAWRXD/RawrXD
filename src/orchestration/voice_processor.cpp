#include "voice_processor.hpp"
#include <iostream>

VoiceProcessor::VoiceProcessor(void* parent)
    : m_parent(parent)
    , m_recording(false)
{
}

VoiceProcessor::~VoiceProcessor() = default;

void VoiceProcessor::setConfig(const Config& config) {
    m_config = config;
}

VoiceProcessor::Config VoiceProcessor::getConfig() const {
    return m_config;
}

bool VoiceProcessor::startRecording() {
    m_recording = true;
    return true;
}

bool VoiceProcessor::stopRecording() {
    m_recording = false;
    return true;
}

bool VoiceProcessor::isRecording() const {
    return m_recording;
}

std::string VoiceProcessor::transcribeAudio(const std::vector<uint8_t>& audioData) {
    (void)audioData;
    return "[Transcription stub]";
}

std::string VoiceProcessor::detectIntent(const std::string& transcript) {
    (void)transcript;
    return "[Intent stub]";
}

std::string VoiceProcessor::generatePlan(const std::string& intent, const std::string& context) {
    (void)intent;
    (void)context;
    return "[Plan stub]";
}

bool VoiceProcessor::speakText(const std::string& text) {
    (void)text;
    return true;
}
