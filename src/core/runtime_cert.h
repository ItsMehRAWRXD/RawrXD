// The shared extension runtime certificate.
//
// The certificate lives in the runtime library so that the production IDE
// binary and the standalone certification exercise the same code.

#ifndef RAWRXD_RUNTIME_CERT_H
#define RAWRXD_RUNTIME_CERT_H

namespace RawrXD {
namespace Extensions {

// Runs the extension runtime certificate.
//
//   workDir     a directory the certificate may write into
//   receiptPath where the JSON receipt is written (may be null)
//
// Returns 0 when every check passed.
int RunExtensionRuntimeCertificate(const char* workDir, const char* receiptPath);

} // namespace Extensions
} // namespace RawrXD

#endif // RAWRXD_RUNTIME_CERT_H
