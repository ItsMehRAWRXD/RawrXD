# G12-02 RELATED — M4 Authenticode remasure

ASOF=2026-11-13T22:24:00-05:00  
RESULT=RELATED · Authenticode=**ABSENT**  
PROMOTE=0 · INVENT_PASS=0 · CROSS_SHA_CREDIT=0 · NOT_RUN!=PASS

## Measured (Get-AuthenticodeSignature)

| Artifact | SHA256 (prefix) | Status | Authenticode |
|----------|-----------------|--------|--------------|
| `installer/SetupWizard.exe` (pre-rebuild) | `1E362C87…` | NotSigned | ABSENT |
| `installer/SetupWizard.exe` (post `build_setupwizard_m4.bat`) | `695E376F45C694E45306B2C7CF8DE1D0532BC0E657492390B26E589244F84610` | NotSigned | ABSENT |
| `…/M4_FULL_INSTALLER_WORK/out/RawrXD_M4_FullInstaller_perUser_7.4.0.msi` | `E689453FE371D071643189B7E30774FCB8AEF6A6868E7416946B27F11F95ED71` | NotSigned | ABSENT |
| packaging copy of same MSI | `E689453F…` | NotSigned | ABSENT |

## Signed MSI blocker (documented)

- Local CurrentUser/LocalMachine My stores: no RawrXD product code-signing certificate with private key suitable for `signtool sign`.
- Observed unrelated private-key cert: `CN=SteelSeries A/S` (not product authority; must not use for RawrXD MSI).
- MSI silent install prior RUNTIME_REACHED remains cited under M4_FULL_INSTALLER_MSI_001 / E689453F — unsigned.

## Offline SetupWizard

- Rebuilt via `installer/build_setupwizard_m4.bat` EXIT=0 linking `SetupWizard.cpp` + `SetupWizard_Offline_Fs.cpp`.
- Authenticode still ABSENT after rebuild.

## Artifacts

- `receipts/m4_authcode_20261113_222135/run.meta.txt`
- `receipts/m4_authcode_20261113_222135/codesign_store_probe.txt`
