#!/bin/bash
# build_appimage.sh
# Phase H.1 Batch 3/5: Linux AppImage Build

set -e

VERSION="${1:-1.0.0}"
ARCH="${2:-x86_64}"
OUTPUT_DIR="${3:-./output}"
APP_NAME="RawrXD"

# Create AppDir structure
echo "Creating AppDir..."
APPDIR="${OUTPUT_DIR}/RawrXD-${VERSION}-${ARCH}.AppDir"
mkdir -p "${APPDIR}/usr/bin"
mkdir -p "${APPDIR}/usr/lib"
mkdir -p "${APPDIR}/usr/share/applications"
mkdir -p "${APPDIR}/usr/share/icons/hicolor/256x256/apps"

# Copy binary
cp "../../build/RawrXD" "${APPDIR}/usr/bin/"
chmod +x "${APPDIR}/usr/bin/RawrXD"

# Create desktop entry
cat > "${APPDIR}/usr/share/applications/rawrxd.desktop" << EOF
[Desktop Entry]
Name=RawrXD Sovereign
Exec=RawrXD
Icon=rawrxd
Type=Application
Categories=Development;AI;
Comment=Sovereign AI Runtime
EOF

cp "${APPDIR}/usr/share/applications/rawrxd.desktop" "${APPDIR}/"

# Create AppRun
cat > "${APPDIR}/AppRun" << 'EOF'
#!/bin/bash
SELF=$(readlink -f "$0")
HERE=${SELF%/*}
export PATH="${HERE}/usr/bin:${PATH}"
export LD_LIBRARY_PATH="${HERE}/usr/lib:${LD_LIBRARY_PATH}"
exec "${HERE}/usr/bin/RawrXD" "$@"
EOF
chmod +x "${APPDIR}/AppRun"

# Download appimagetool if not present
APPIMAGETOOL="${OUTPUT_DIR}/appimagetool-${ARCH}.AppImage"
if [ ! -f "$APPIMAGETOOL" ]; then
    echo "Downloading appimagetool..."
    wget -q "https://github.com/AppImage/AppImageKit/releases/download/continuous/appimagetool-${ARCH}.AppImage" -O "$APPIMAGETOOL"
    chmod +x "$APPIMAGETOOL"
fi

# Build AppImage
echo "Building AppImage..."
APPIMAGE_NAME="RawrXD-${VERSION}-${ARCH}.AppImage"
"$APPIMAGETOOL" "$APPDIR" "${OUTPUT_DIR}/${APPIMAGE_NAME}"

# GPG sign if key available
if [ -n "$GPG_KEY_ID" ]; then
    echo "GPG signing AppImage..."
    gpg --armor --detach-sign --default-key "$GPG_KEY_ID" "${OUTPUT_DIR}/${APPIMAGE_NAME}"
fi

# Generate checksum
cd "$OUTPUT_DIR"
sha256sum "$APPIMAGE_NAME" > "${APPIMAGE_NAME}.sha256"

echo "AppImage build complete: ${OUTPUT_DIR}/${APPIMAGE_NAME}"
