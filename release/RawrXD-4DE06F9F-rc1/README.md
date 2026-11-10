# RawrXD portable release candidate

This package preserves the certified IDE executable with SHA-256
`4DE06F9F0D7C4FA59926A1BD89041DB7FE75DE0332DBA783A968D3B4105D8BE6`.
The package is a release candidate. Its manifest verifies payload integrity;
integrity verification alone does not establish G01–G15 release acceptance.

## Requirements

Windows 10/11 x64, Windows PowerShell 5.1 or newer, and an installed AMD Vulkan
driver for Deep2 GPU inference. Microsoft C++ runtime DLLs are included using
the Visual Studio redistributable payload. Windows and GPU drivers are external
prerequisites. Ollama must be installed separately for the Ollama backend;
the default local endpoint is `http://localhost:11434`. No models are bundled.
Select an installed Ollama model or supply a supported GGUF model for Deep2.
Compiling C/C++ projects requires an installed compiler and Windows SDK.

## Start and verify

Extract the entire archive into a new directory. In PowerShell run
`& .\Verify-PortableRelease.ps1` to verify all manifest entries, then
`& .\Start-RawrXD.ps1`. An optional `-ProjectPath` selects an existing project
directory or file. The launcher checks integrity before starting the IDE.
It makes no execution-policy changes. Alternatively launch the IDE executable
directly after verification.

The IDE currently stores session state in `%LOCALAPPDATA%\RawrXD`.
The legacy `--user-data-dir` argument is not a verified profile-isolation
mechanism for this binary. Back up that directory before upgrade or rollback.
Avoid running two copies against the same profile concurrently.

## Upgrade and rollback

Close the IDE and wait for its workers to exit. Keep the previous extracted
release and a backup of `%LOCALAPPDATA%\RawrXD`. Extract the new release into a
separate directory, verify it, and start it. To roll back, close the new IDE,
restore the saved profile if necessary, verify the previous release, and launch
the previous executable. Do not overwrite a running executable or mix binaries
and sidecars from different releases. Clean installation and rollback on a
separate Windows installation still require an acceptance receipt.

## Evidence and limits

`manifest.json` records both executable hashes, every immutable payload file,
and the source checkout revision used when packaging. That revision identifies
the packaging context; it is not a claim that the legacy executable was built
from the current dirty checkout. `checksums.sha256` supports external checking.
Mutable logs, caches, model weights, user settings, and secrets are excluded.

G01–G15 require receipts that identify the tested package, actual runtime path,
observed results, and limitations. Historical receipt labels are not automatic
proof of the broader release gates. Freeze Control synchronization is deferred
and does not affect local IDE acceptance.
