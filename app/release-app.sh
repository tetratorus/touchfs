#!/bin/bash
set -e

if [ -z "$1" ]; then
  echo "Usage: ./release-app.sh v1.0.0"
  exit 1
fi

VERSION=$1
DIST_IDENTITY="Developer ID Application: Leonard Tan (X44L3QQYVR)"
DMG_NAME="TouchFS-${VERSION}.dmg"

echo "=== Building Swift app ==="
xcodegen generate
rm -rf /Users/lentan/Library/Developer/Xcode/DerivedData/TouchFS-*
xcodebuild -project TouchFS.xcodeproj -scheme TouchFS -configuration Release clean build

BUILD_DIR=$(xcodebuild -project TouchFS.xcodeproj -scheme TouchFS -configuration Release -showBuildSettings 2>/dev/null | grep " BUILD_DIR = " | sed 's/.*= //')
APP="$BUILD_DIR/Release/TouchFS.app"

echo "=== Signing app ==="
codesign --force --options runtime --sign "$DIST_IDENTITY" "$APP"

echo "=== Notarizing ==="
rm -f TouchFS.zip
ditto -c -k --keepParent "$APP" TouchFS.zip
xcrun notarytool submit TouchFS.zip --keychain-profile touchfs --wait
xcrun stapler staple "$APP"
rm -f TouchFS.zip

echo "=== Creating DMG ==="
rm -f "$DMG_NAME"
STAGING=$(mktemp -d)
cp -R "$APP" "$STAGING/"
ln -s /Applications "$STAGING/Applications"

hdiutil create -volname "TouchFS" -srcfolder "$STAGING" -ov -format UDZO "$DMG_NAME"
rm -rf "$STAGING"

# Sign and notarize the DMG.
codesign --force --sign "$DIST_IDENTITY" "$DMG_NAME"
xcrun notarytool submit "$DMG_NAME" --keychain-profile touchfs --wait
xcrun stapler staple "$DMG_NAME"

SHA=$(shasum -a 256 "$DMG_NAME" | awk '{print $1}')

echo "=== Done ==="
echo "DMG: $DMG_NAME"
echo "SHA: $SHA"
