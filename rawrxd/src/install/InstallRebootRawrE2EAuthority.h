#pragma once

// Install reboot rawr E2E authority - Gates install/reboot/rawr end-to-end completion
// This authority ensures the CLI-only install/reboot/rawr workflow completes successfully

namespace rawrxd::install
{
    // Certify install reboot rawr
    void certInstallRebootRawr();
    
    // Write install reboot rawr E2E receipt
    void writeInstallRebootRawrE2EReceipt();
}
