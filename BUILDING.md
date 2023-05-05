# Build Instructions

This application is built with cargo. rustc 1.69+ is required.

**Cargo**

`cargo build --release` is sufficient.

**Makefile**

Build the binary and install it to /usr/local/bin
```
make
make test
sudo make prefix=/usr/local install
```

**Creating a release**

The official release process includes a `build.py` script that builds the
application and creates installer packages for the supported architectures
and operating systems. Official .deb and .rpm packages include a man page
and bash completion script.

## Required Packages for build.py

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

### Source Release
Create a source release. Make sure the git directory doesn't have any files
that aren't tracked: `git clean -dxi`

```
python3 build.py --source
```

This will put a source tarball in `build/`

### Build Binaries
Binaries should be built from a source release created with `build.py --source`

### Linux build
```
python3 build.py --os linux --arch amd64 --arch arm64 --test-arch amd64
```

The test architecture should be the architecture of the host machine that
you're building on because it will also run tests. Striping the binaries
requires the package binutils-x86_64-linux-gnu if you're running from an
x86_64 host.

### .deb and .rpm packages
Created in Docker containers. `build.py` follows the standard packging
procedure for debian and fedora to create packages.

### Manpage Generation
Manpages are converted from markdown using pandoc. Running `make` in the
`docs/` directory will generate the manpage.

### macOS build
```
python3 build.py --os macos -a amd64 -a arm64 --test-arch arm64
```

### Windows build
```
python3 build.py --os windows --arch amd64 --test-arch amd64 --win-installer
```

Specifying --win-installer will use Inno Setup to build the windows
installer

### SHA256SUMS file
Create SHA-256 checksums of all build artifacts in the specified directory

```
python3 build.py --checksum build
```
