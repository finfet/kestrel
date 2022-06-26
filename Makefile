prefix = /usr

all: build

build:
	cargo build --release

test:
	cargo test --workspace --release

install:
	mkdir -p $(DESTDIR)$(prefix)/bin/
	install target/release/kestrel $(DESTDIR)$(prefix)/bin/kestrel

clean:
	-cargo clean

distclean: clean

uninstall:
	-rm -f $(DESTDIR)$(prefix)/bin/kestrel

.PHONY: all build test install clean distclean uninstall
