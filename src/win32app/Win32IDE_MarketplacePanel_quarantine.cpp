// Fail-closed marketplace panel entry points when RAWRXD_OPTIONAL_CLOUD=OFF.
#include "Win32IDE.h"

void Win32IDE::initMarketplace()
{
    // No registry / marketplace HTTP — panel not wired in default binary.
}

bool Win32IDE::handleMarketplaceCommand(int)
{
    return false;
}

void Win32IDE::cmdMarketplaceShow()
{
}
