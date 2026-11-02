.PHONY: setup install_sudo build xcode-build run install uninstall publish_flyio
setup:
	./setup.sh
install_sudo: setup
publish_flyio:
	bash scripts/publish-flyio.sh
build:
	./build.sh
xcode-build:
	xcodegen generate
	xcodebuild -project WGApp.xcodeproj -scheme WGApp -configuration Debug -derivedDataPath build build
run: build
	./build/Build/Products/Debug/WGApp.app/Contents/MacOS/WGApp
install: setup
	sudo /usr/bin/ditto build/Build/Products/Debug/WGApp.app /Applications/WGApp.app
	@echo "Installed /Applications/WGApp.app and refreshed the root launcher/sudoers rule."
uninstall:
	./uninstall.sh
	sudo rm -rf /Applications/WGApp.app
