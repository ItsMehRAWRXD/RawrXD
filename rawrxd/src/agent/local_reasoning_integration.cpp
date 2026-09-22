#include "local_reasoning_integration.hpp"

static LocalReasoningEngine s_instance;

LocalReasoningEngine& LocalReasoningIntegration::instance() {
    return s_instance;
}
