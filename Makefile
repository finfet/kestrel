ARCH = amd64 # amd64, arm64
ALTARCH = x86_64 # x86_64, aarch64
BUILD_TARGET = x86_64-unknown-linux-musl # aarch64-unknown-linux-musl
BIN_PACKAGE_DIR = kestrel-linux-v$(version)-$(ARCH)
BUILD_TARGET = x86_64-unknown-linux-musl

version := 0.11.0
deb_rev := 1
deb_build_dir := build/deb_$(ARCH)
deb_app_dir := kestrel_$(version)-$(deb_rev)_$(ARCH)
rpm_build_dir := build/rpm_$(ARCH)
current_dir = $(shell pwd)
prefix := /usr

all: build

linux-amd64:
	$(MAKE) ARCH=amd64 ALTARCH=x86_64 BUILD_TARGET=x86_64-unknown-linux-musl package

linux-arm64:
	$(MAKE) ARCH=arm64 ALTARCH=aarch64 BUILD_TARGET=aarch64-unknown-linux-musl package

rpm-amd64:
	$(MAKE) ARCH=amd64 ALTARCH=x86_64 BUILD_TARGET=x86_64-unknown-linux-musl rpm

rpm-arm64:
	$(MAKE) ARCH=arm64 ALTARCH=aarch64 BUILD_TARGET=aarch64-unknown-linux-musl rpm

deb-amd64:
	$(MAKE) ARCH=amd64 ALTARCH=x86_64 BUILD_TARGET=x86_64-unknown-linux-musl deb

deb-arm64:
	$(MAKE) ARCH=arm64 ALTARCH=aarch64 BUILD_TARGET=aarch64-unknown-linux-musl deb

all-linux: linux-amd64 linux-arm64 rpm-amd64 rpm-arm64 deb-amd64 deb-arm64
	-rm -rf build/release-v$(version)
	mkdir -p build/release-v$(version)
	cp build/deb_amd64/*.deb build/release-v$(version)/
	cp build/deb_arm64/*.deb build/release-v$(version)/
	cp build/kestrel-linux-v$(version)-amd64.tar.gz build/release-v$(version)/
	cp build/kestrel-linux-v$(version)-arm64.tar.gz build/release-v$(version)/
	cp build/rpm_amd64/rpmbuild/RPMS/x86_64/*.rpm build/release-v$(version)/
	cp build/rpm_arm64/rpmbuild/RPMS/aarch64/*rpm build/release-v$(version)/
	cd build/release-v$(version) && sha256sum -b * > SHA256SUMS.txt

build:
	cargo build --release

build-target:
	cargo build --release --target $(BUILD_TARGET)

test:
	cargo test --workspace --release

install:
	mkdir -p $(DESTDIR)$(prefix)/bin/
	install target/release/kestrel $(DESTDIR)$(prefix)/bin/kestrel

deb: clean-deb package
	mkdir -p $(deb_build_dir)
	cp build/$(BIN_PACKAGE_DIR).tar.gz $(deb_build_dir)
	tar -C $(deb_build_dir) -xf $(deb_build_dir)/$(BIN_PACKAGE_DIR).tar.gz
	cp debian/control $(deb_build_dir)
	sed -i "s/Architecture: .*/Architecture: $(ARCH)/g" $(deb_build_dir)/control
	sed -i "s/Version: .*/Version: $(version)/g" $(deb_build_dir)/control
	install -D -m 644 $(deb_build_dir)/control $(deb_build_dir)/$(deb_app_dir)/DEBIAN/control
	gzip $(deb_build_dir)/$(BIN_PACKAGE_DIR)/man/kestrel.1
	install -D -m 755 $(deb_build_dir)/$(BIN_PACKAGE_DIR)/kestrel $(deb_build_dir)/$(deb_app_dir)/usr/bin/kestrel
	install -D -m 644 $(deb_build_dir)/$(BIN_PACKAGE_DIR)/completion/kestrel.bash-completion $(deb_build_dir)/$(deb_app_dir)/usr/share/bash-completion/completions/kestrel
	install -D -m 644 $(deb_build_dir)/$(BIN_PACKAGE_DIR)/LICENSE.txt $(deb_build_dir)/$(deb_app_dir)/usr/doc/kestrel/LICENSE.txt
	install -D -m 644 $(deb_build_dir)/$(BIN_PACKAGE_DIR)/THIRD-PARTY-LICENSE.txt $(deb_build_dir)/$(deb_app_dir)/usr/doc/kestrel/THIRD-PARTY-LICENSE.txt
	install -D -m 644 $(deb_build_dir)/$(BIN_PACKAGE_DIR)/man/kestrel.1.gz $(deb_build_dir)/$(deb_app_dir)/usr/man/man1/kestrel.1.gz
	dpkg-deb --build --root-owner-group $(deb_build_dir)/$(deb_app_dir)

rpm: clean-rpm package
	mkdir -p $(rpm_build_dir)/rpmbuild/BUILD
	mkdir -p $(rpm_build_dir)/rpmbuild/RPMS
	mkdir -p $(rpm_build_dir)/rpmbuild/SOURCES
	mkdir -p $(rpm_build_dir)/rpmbuild/SPECS
	mkdir -p $(rpm_build_dir)/rpmbuild/SRPMS
	cp build/$(BIN_PACKAGE_DIR).tar.gz $(rpm_build_dir)/rpmbuild/SOURCES/
	cp kestrel.spec $(rpm_build_dir)/rpmbuild/SPECS/kestrel.spec
	rpmbuild -bb --target $(ALTARCH) --define "_topdir $(current_dir)/$(rpm_build_dir)/rpmbuild" $(rpm_build_dir)/rpmbuild/SPECS/kestrel.spec

package: test build-target
	mkdir -p build/$(BIN_PACKAGE_DIR)
	install -D -m 644 completion/kestrel.bash-completion build/$(BIN_PACKAGE_DIR)/completion/kestrel.bash-completion
	install -D -m 755 target/$(BUILD_TARGET)/release/kestrel build/$(BIN_PACKAGE_DIR)/kestrel
	install -D -m 644 LICENSE.txt build/$(BIN_PACKAGE_DIR)/LICENSE.txt
	install -D -m 644 THIRD-PARTY-LICENSE.txt build/$(BIN_PACKAGE_DIR)/THIRD-PARTY-LICENSE.txt
	install -D -m 644 docs/man/kestrel.1 build/$(BIN_PACKAGE_DIR)/man/kestrel.1
	tar -C build -czpvf build/$(BIN_PACKAGE_DIR).tar.gz $(BIN_PACKAGE_DIR)

clean-deb:
	-rm -rf $(deb_build_dir)

clean-rpm:
	-rm -rf $(rpm_build_dir)

clean:
	-rm -rf build

.PHONY: all all-linux build build-target deb rpm package clean-deb clean-rpm clean
