// The extension runtime certificate, run from the production IDE binary.
//
// The certificate lives in the shared extension runtime library, so this
// mode exercises exactly the code the IDE ships rather than a copy of it.
//
//      RawrXD-Win32IDE-Native.exe --extension-cert <work-dir> [receipt-path]

#ifndef RAWRXD_IDE_EXTENSION_CERT_H
#define RAWRXD_IDE_EXTENSION_CERT_H

// Runs the extension runtime certificate inside the IDE binary.
// Returns 0 when every check passed.
int RunExtensionCertProbe(int argc, char** argv);

#endif // RAWRXD_IDE_EXTENSION_CERT_H
