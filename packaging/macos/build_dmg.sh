#!/bin/bash
# build_dmg.sh
# Phase H.1 Batch 2/5: macOS DMG Builder with Notarization

set -e

VERSION="${1:-1.0.0}"
OUTPUT_DIR="${2:-./output}"
APP_NAME="RawrXD"
BUNDLE_ID="ai.rawrxd.sovereign"

# Create app bundle structure
echo "Creating app bundle..."
mkdir -p "${OUTPUT_DIR}/${APP_NAME}.app/Contents/MacOS"
mkdir -p "${OUTPUT_DIR}/${APP_NAME}.app/Contents/Resources"

# Copy binary
cp "../../build/RawrXD" "${OUTPUT_DIR}/${APP_NAME}.app/Contents/MacOS/"
chmod +x "${OUTPUT_DIR}/${APP_NAME}.app/Contents/MacOS/RawrXD"

# Create Info.plist
cat > "${OUTPUT_DIR}/${APP_NAME}.app/Contents/Info.plist" << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleExecutable</key>
    <string>RawrXD</string>
    <key>CFBundleIdentifier</key>
    <string>${BUNDLE_ID}</string>
    <key>CFBundleName</key>
    <string>RawrXD Sovereign</string>
    <key>CFBundleVersion</key>
    <string>${VERSION}</string>
    <key>CFBundlePackageType</key>
    <string>APPL</string>
    <key>LSMinimumSystemVersion</key>
    <string>11.0</string>
</dict>
</plist>
EOF

# Sign app bundle
if [ -n "$CODESIGN_IDENTITY" ]; then
    echo "Signing app bundle..."
    codesign --force --deep --sign "$CODESIGN_IDENTITY" \
        --entitlements entitlements.plist \
        "${OUTPUT_DIR}/${APP_NAME}.app"
fi

# Create DMG
echo "Creating DMG..."
DMG_NAME="RawrXD-${VERSION}-macOS.dmg"
VOLUME_NAME="RawrXD ${VERSION}"

hdiutil create -volname "$VOLUME_NAME" -srcfolder "${OUTPUT_DIR}/${APP_NAME}.app" \
    -ov -format UDZO "${OUTPUT_DIR}/${DMG_NAME}"

# Notarize if credentials provided
if [ -n "$APPLE_ID" ] && [ -n "$APPLE_APP_SPECIFIC_PASSWORD" ]; then
    echo "Submitting for notarization..."
    xcrun notarytool submit "${OUTPUT_DIR}/${DMG_NAME}" \
        --apple-id "$APPLE_ID" \
        --password "$APPLE_APP_SPECIFIC_PASSWORD" \
        --team-id "$APPLE_TEAM_ID" \
        --wait
    
    echo "Stapling notarization ticket..."
    xcrun stapler staple "${OUTPUT_DIR}/${DMG_NAME}"
fi

# Generate checksum
cd "$OUTPUT_DIR"
shasum -a 256 "$DMG_NAME" > "${DMG_NAME}.sha256"

echo "DMG build complete: ${OUTPUT_DIR}/${DMG_NAME}"
