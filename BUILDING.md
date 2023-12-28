# Build Instructions

This application is built with cargo. rustc 1.70+ is required.

**Cargo**

`cargo build --release --locked` is sufficient.

**Makefile**

Build the binary and install it to /usr/local/bin
```
make
make test
sudo make prefix=/usr/local install
```

**Creating a release**

The Makefile includes the ability to build .rpm and .deb packages as well as
a tarball containing the binary and associated docs and man pages.

## Required Packages

**Linux**

- gcc and the debian build-essential package or equivalent
- When building from x86_64 to aarch64 the aarch64 linker
  `gcc-aarch64-linux-gnu` is needed.
- cargo targets: x86_64-unknown-linux-musl, aarch64-unknown-linux-musl,
  x86_64-unknown-linux-gnu

**macOS**

- Xcode with command line tools
- cargo targets: x86_64-apple-darwin, aarch64-apple-darwin

**Windows**

- Visual studio with MSVC toolchain
- cargo targets: x86_64-pc-windows-msvc
- Inno Setup 6.2+ for the windows installer. Make sure iscc.exe is on
  the path.

## Building

Create the linux .deb, .rpm, and binary releases
```
make all-linux
```

### Manpage Generation
Manpages are converted from markdown using pandoc. Running `make` in the
`docs/` directory will generate the manpage.
