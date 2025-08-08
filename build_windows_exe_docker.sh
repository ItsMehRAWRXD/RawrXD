#!/usr/bin/env bash
set -euo pipefail

IMAGE="cdrx/pyinstaller-windows"
SCRIPT="pyinstaller --noconfirm --onefile --console --name AICodeGenerator ai_coder_windows.py"

if ! command -v docker >/dev/null 2>&1; then
  echo "Docker is required to run this script." >&2
  exit 1
fi

echo "Pulling $IMAGE (if not present)..."
docker pull "$IMAGE" >/dev/null || true

echo "Building Windows .exe via PyInstaller in Docker..."
docker run --rm -v "$PWD":/src "$IMAGE" "$SCRIPT"

echo
if [[ -f dist/AICodeGenerator.exe ]]; then
  echo "✅ Build complete: dist/AICodeGenerator.exe"
else
  echo "ℹ️ Check the dist/ directory for the built executable."
fi