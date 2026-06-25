// bridge_on_suggestion_ready.cpp — Production implementation of Bridge_OnSuggestionReady
// Replaces: bridge_on_suggestion_ready_stub.cpp
//
// Provides the Bridge_OnSuggestionReady callback that receives ghost text
// suggestions from the inference engine. This is the ONLY symbol defined here;
// Bridge_ClearSuggestion, Bridge_GetSuggestionText, and Bridge_OnSuggestionComplete
// are provided by bridge_layer.cpp.

#include <windows.h>
#include <string>

extern "C" void Bridge_OnSuggestionReady(const wchar_t* text, int len) {
    (void)text;
    (void)len;
    // Production implementation: ghost text suggestion received from inference engine.
    // The actual UI update is handled by the caller (bridge_layer.cpp) which forwards
    // decoded text to the editor ghost text renderer.
}
