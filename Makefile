prefix = /usr

all: build

build:
	cargo build --release

install:
	install -D target/release/kestrel $(DESTDIR)$(prefix)/bin/kestrel

clean:
	-cargo clean

distclean: clean

uninstall:
	-rm -f $(DESTDIR)$(prefix)/bin/kestrel

.PHONY: all install clean distclean uninstall
