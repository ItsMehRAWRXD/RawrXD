#include "Win32IDE.h"

// The bridge smoke target is intentionally headless.  It needs the bridge's
// logging call sites but must not pull the full IDE window implementation into
// a recovery-only executable.  This test-only sink preserves the production
// bridge lifecycle while keeping the target's dependency surface explicit.
void Win32IDE::logMessage(const std::string&, const std::string&)
{
}
