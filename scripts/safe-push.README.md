# RawrXD safe Git push wrapper

Prevents an empty source ref from producing a deletion refspec (`:branch`).
Only accepts existing **local branches** and explicit branch destinations.
Uses a fully qualified `refs/heads/source:refs/heads/destination` refspec.
No force-push or deletion option is exposed.

## Usage

```powershell
./safe-push.ps1 -Source feat/hexmag-polymorphic-repeat-tuner-masm -DryRun
./safe-push.ps1 -Source feat/hexmag-polymorphic-repeat-tuner-masm
./safe-push.ps1 -Source feat/gpu-quant-dot -Destination feat/gpu-quant-dot
```

The wrapper is not installed globally and cannot prevent direct `git push`
commands or pushes from other tools. Protect important remote branches with
GitHub rulesets requiring pull requests and disallowing deletion.

This drop does not modify the GGUF reader: the reported GGUF_BOOL correction
is already committed upstream.
