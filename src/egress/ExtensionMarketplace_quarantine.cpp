// Fail-closed ExtensionMarketplace — RAWRXD_OPTIONAL_CLOUD=OFF only.
#include "../marketplace/extension_marketplace.hpp"
#include "../marketplace/extension_package_local.hpp"

namespace RawrXD {
namespace Extensions {

static ExtResult off() { return ExtResult::error("OPTIONAL_CLOUD=OFF", -1); }

ExtensionMarketplace& ExtensionMarketplace::instance()
{
    static ExtensionMarketplace s;
    return s;
}

ExtensionMarketplace::ExtensionMarketplace() = default;
ExtensionMarketplace::~ExtensionMarketplace() = default;

ExtResult ExtensionMarketplace::setInstallDirectory(const std::string&) { return off(); }
ExtResult ExtensionMarketplace::setCacheDirectory(const std::string&) { return off(); }
ExtResult ExtensionMarketplace::setRegistryUrl(const std::string&) { return off(); }
ExtResult ExtensionMarketplace::applyPolicy(const EnterprisePolicyConfig&) { return off(); }
ExtResult ExtensionMarketplace::checkPolicy(const ExtensionManifest&) { return off(); }
ExtResult ExtensionMarketplace::search(const ExtensionSearchQuery&, ExtensionSearchResponse&)
{
    return off();
}
ExtResult ExtensionMarketplace::getExtensionDetails(const std::string&, ExtensionSearchResult&)
{
    return off();
}
std::vector<ExtensionManifest> ExtensionMarketplace::listInstalled() const { return {}; }
std::vector<ExtensionManifest> ExtensionMarketplace::listEnabled() const { return {}; }
ExtResult ExtensionMarketplace::installFromVsix(const std::string& path)
{
    return Local::InstallPackage(path);
}
ExtResult ExtensionMarketplace::installFromPackage(const std::string& path)
{
    return Local::InstallPackage(path);
}
ExtensionPackageFormat ExtensionMarketplace::detectPackageFormat(
    const std::string& path) const
{
    return Local::DetectFormat(path);
}
const IdeExtensionFormatInfo* ExtensionMarketplace::ideExtensionCatalog(size_t& outCount)
{
    return Local::IdeCatalog(outCount);
}
const char* ExtensionMarketplace::packageFormatName(ExtensionPackageFormat fmt)
{
    return Local::FormatName(fmt);
}
ExtResult ExtensionMarketplace::installFromRegistry(const std::string&,
                                                    const std::string&)
{
    return off();
}
ExtResult ExtensionMarketplace::installFromUrl(const std::string&) { return off(); }
ExtResult ExtensionMarketplace::uninstall(const std::string&) { return off(); }
ExtResult ExtensionMarketplace::update(const std::string&) { return off(); }
ExtResult ExtensionMarketplace::updateAll() { return off(); }
ExtResult ExtensionMarketplace::enable(const std::string&) { return off(); }
ExtResult ExtensionMarketplace::disable(const std::string&) { return off(); }
ExtResult ExtensionMarketplace::activate(const std::string&, const std::string&) { return off(); }
ExtResult ExtensionMarketplace::deactivate(const std::string&) { return off(); }
ExtensionState ExtensionMarketplace::getState(const std::string&) const
{
    return ExtensionState::NOT_INSTALLED;
}
ExtResult ExtensionMarketplace::getManifest(const std::string&, ExtensionManifest&) const
{
    return off();
}
ExtResult ExtensionMarketplace::checkDependencies(const std::string&, std::vector<std::string>&)
{
    return off();
}
ExtResult ExtensionMarketplace::installWithDependencies(const std::string&) { return off(); }
ExtResult ExtensionMarketplace::getDependencyTree(const std::string&, std::vector<std::string>&)
{
    return off();
}
ExtResult ExtensionMarketplace::resolveDependencies(const std::string&, std::vector<std::string>&)
{
    return off();
}
ExtResult ExtensionMarketplace::extractVsix(const std::string&, const std::string&) { return off(); }
ExtResult ExtensionMarketplace::parseManifest(const std::string&, ExtensionManifest&) { return off(); }
ExtResult ExtensionMarketplace::verifySignature(const std::string&) { return off(); }
bool ExtensionMarketplace::semverSatisfies(const std::string&, const std::string&) { return false; }
ExtResult ExtensionMarketplace::httpDownload(const std::string&, const std::string&) { return off(); }
ExtResult ExtensionMarketplace::cacheExtension(const std::string&) { return off(); }
ExtResult ExtensionMarketplace::clearCache() { return off(); }
ExtensionMarketplace::CacheStats ExtensionMarketplace::getCacheStats() const { return {}; }
void ExtensionMarketplace::addEventListener(MarketplaceEventCallback, void*) {}
void ExtensionMarketplace::removeEventListener(MarketplaceEventCallback) {}
void ExtensionMarketplace::emitEvent(const MarketplaceEvent&) {}
ExtensionMarketplace::MarketplaceStats ExtensionMarketplace::getStats() const { return {}; }
void ExtensionMarketplace::shutdown() {}

} // namespace Extensions
} // namespace RawrXD
