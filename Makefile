APP      = touchfs.app
BINARY   = $(APP)/Contents/MacOS/touchfs
IDENTITY = Apple Development: Leonard Tan (288HB2PKTS)

.PHONY: build clean install

build:
	mkdir -p $(APP)/Contents/MacOS
	cp Info.plist $(APP)/Contents/Info.plist
	cp embedded.provisionprofile $(APP)/Contents/embedded.provisionprofile
	go build -o $(BINARY) .
	codesign --force --options runtime --sign "$(IDENTITY)" --entitlements entitlements.plist $(APP)

install:
	@echo "Run: ln -sf $(CURDIR)/$(BINARY) /usr/local/bin/touchfs"

clean:
	rm -rf $(APP)
