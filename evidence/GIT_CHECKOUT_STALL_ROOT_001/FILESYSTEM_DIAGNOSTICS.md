# Filesystem diagnostics

| Check | Result | Meaning |
|---|---|---|
| Destination volume | `G:` NTFS | Normal filesystem type observed |
| Volume size | 4,000,650,883,072 bytes | — |
| Free space | 1,489,250,402,304 bytes | Not a capacity failure |
| Candidate files on disk | 116,549 at observation | Partial materialization |
| ExtensionHost worker on disk | absent | Consistent with incomplete checkout |
| `fltmc filters` | access denied (`0x80070005`) | Filter-driver inventory unavailable under current permissions |
| Defender status | enabled, real-time enabled, IOAV enabled | Security scanning is possible; no causal interference established |
| Path/access errors | none captured from Git command output | No demonstrated access-denied/path-length failure |

No security software or filesystem setting was changed. `Get-MpComputerStatus` confirms Defender is enabled, but does not establish that it is blocking Git.

