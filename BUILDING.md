# Build Instructions

## Required Software

This application is built with cargo. rustc 1.57+ is required.

There is a Python3 build script that runs cargo build commands and creates
tarballs automatically. Running the build steps manually without the
build script can be done but is much more laborious and is not recommended.

- Linux
  - Default gcc linker required by cargo. on debian: build-essential
  - cargo targets: x86_64-unknown-linux-musl, aarch64-unknown-linux-musl
  - gcc aarch64 linker: on debian: gcc-aarch64-linux-gnu
- macOS
  - Xcode with command line tools
  - cargo targets: x86_64-apple-darwin, aarch64-apple-darwin
- Windows
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

Build from a source release created with `build.py --source`

### Linux build
The test architecture should be the architecture of the host machine that
you're building on because it will also run tests. Striping the binaries
requires the package binutils-x86_64-linux-gnu if you're running from an
x86_64 host.

```
python3 build.py --os linux --arch amd64 --arch arm64 --test-arch amd64
```

### Debian Package

Requires a debian based distribution with access to cargo and rustc >=1.57.

It is a good idea to build in a clean VM or container.

Tested on Ubuntu 20.04 and 22.04. Debian packages for arm64 can be built
on a native arm64 machine or container. A container on Apple M1 works.

Packages required: build-essential devscripts debhelper fakeroot bash-completion cargo

Using a source release, create a new directory and move the `.tar.gz`
file into it. Copy the `.tar.gz` as `kestrel-_x.x.x.orig.tar.gz`.
Inside of the extracted source package, run `debuild -us -uc -b -rfakeroot` to build
a debian package.

### Manpage Generation

Manpages are converted from markdown using pandoc

```
pandoc -s -t man -o kestrel.1 kestrel.1.md
```

### macOS build
```
python3 build.py --os macos -a amd64 -a arm64 --test-arch arm64
```

### Windows build
Specifying --win-installer will use Inno Setup to build the windows
installer

```
python3 build.py --os windows --arch amd64 --test-arch amd64 --win-installer
```

### SHA256SUMS file
Create SHA-256 checksums of all build artifacts in the specified directory

```
python3 build.py --checksum build
```
