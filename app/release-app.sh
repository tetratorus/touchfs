#!/bin/bash
set -e

if [ -z "$1" ]; then
  echo "Usage: ./release-app.sh v1.0.0"
  exit 1
fi

VERSION=$1
DIST_IDENTITY="Developer ID Application: Leonard Tan (X44L3QQYVR)"

echo "=== Building Swift app ==="
xcodegen generate
rm -rf /Users/lentan/Library/Developer/Xcode/DerivedData/TouchFS-*
xcodebuild -project TouchFS.xcodeproj -scheme TouchFS -configuration Release clean build

BUILD_DIR=$(xcodebuild -project TouchFS.xcodeproj -scheme TouchFS -configuration Release -showBuildSettings 2>/dev/null | grep " BUILD_DIR = " | sed 's/.*= //')
APP="$BUILD_DIR/Release/TouchFS.app"

echo "=== Signing ==="
codesign --force --options runtime --sign "$DIST_IDENTITY" "$APP"

echo "=== Notarizing ==="
rm -f TouchFS.zip
ditto -c -k --keepParent "$APP" TouchFS.zip
xcrun notarytool submit TouchFS.zip --keychain-profile touchfs --wait
xcrun stapler staple "$APP"
rm -f TouchFS.zip
ditto -c -k --keepParent "$APP" TouchFS.zip

SHA=$(shasum -a 256 TouchFS.zip | awk '{print $1}')

echo "=== Done ==="
echo "App: $APP"
echo "Zip: TouchFS.zip"
echo "SHA: $SHA"
