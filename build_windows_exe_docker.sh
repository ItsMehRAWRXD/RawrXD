#!/usr/bin/env bash
set -euo pipefail

IMAGE="cdrx/pyinstaller-windows"
ENTRY="ai_coder_windows.py"
APP_NAME="AICodeGenerator"
DISTPATH="."
VERSION_FILE="windows_version_info.txt"
ICON_FILE="app.ico"

ICON_FLAG=""
if [[ -f "$ICON_FILE" ]]; then
  ICON_FLAG=(--icon "$ICON_FILE")
fi

VERSION_FLAG=""
if [[ -f "$VERSION_FILE" ]]; then
  VERSION_FLAG=(--version-file "$VERSION_FILE")
fi

SCRIPT=(pyinstaller --clean --noupx --onedir --console --name "$APP_NAME" --distpath "$DISTPATH" "${ICON_FLAG[@]}" "${VERSION_FLAG[@]}" "$ENTRY")

if ! command -v docker >/dev/null 2>&1; then
  echo "Docker is required to run this script." >&2
  exit 1
fi

echo "Pulling $IMAGE (if not present)..."
docker pull "$IMAGE" >/dev/null || true

echo "Building Windows .exe (onedir) via PyInstaller in Docker..."
docker run --rm -v "$PWD":/src "$IMAGE" bash -lc "${SCRIPT[@]}"

echo
if [[ -f "$APP_NAME/$APP_NAME.exe" ]]; then
  echo "✅ Build complete: $APP_NAME/$APP_NAME.exe"
else
  echo "ℹ️ Check the $APP_NAME/ directory for the built executable."
fi