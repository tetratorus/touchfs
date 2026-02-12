APP      = touchfs.app
BINARY   = $(APP)/Contents/MacOS/touchfs
IDENTITY ?= Apple Development: Leonard Tan (288HB2PKTS)
DIST_IDENTITY = Developer ID Application: Leonard Tan (X44L3QQYVR)
VERSION       ?= dev
LDFLAGS       = -ldflags "-X main.version=$(VERSION)"

.PHONY: build dist notarize clean install

build:
	mkdir -p $(APP)/Contents/MacOS
	cp Info.plist $(APP)/Contents/Info.plist
	cp embedded.provisionprofile $(APP)/Contents/embedded.provisionprofile
	go build $(LDFLAGS) -o $(BINARY) .
	codesign --force --options runtime --sign "$(IDENTITY)" --entitlements entitlements.plist $(APP)

dist:
	mkdir -p $(APP)/Contents/MacOS
	cp Info.plist $(APP)/Contents/Info.plist
	cp embedded.provisionprofile $(APP)/Contents/embedded.provisionprofile
	go build $(LDFLAGS) -o $(BINARY) .
	codesign --force --options runtime --sign "$(DIST_IDENTITY)" --entitlements entitlements.plist $(APP)
	tar czf touchfs.tar.gz $(APP)

notarize: dist
	xcrun notarytool submit touchfs.tar.gz --apple-id YOUR_APPLE_ID --team-id X44L3QQYVR --password YOUR_APP_SPECIFIC_PASSWORD --wait
	xcrun stapler staple $(APP)
	tar czf touchfs.tar.gz $(APP)

install:
	@echo "Run: ln -sf $(CURDIR)/$(BINARY) /usr/local/bin/touchfs"

clean:
	rm -rf $(APP) touchfs.tar.gz
