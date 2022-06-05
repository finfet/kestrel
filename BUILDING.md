# Build Instructions

## Required Software

This application is built with cargo. rustc 1.56+ is required.

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
python3 build.py --archive
```

This will put a source tarball in `build/`

### Build Binaries

Build from a source release created with `build.py -a`

Linux and macOS builds should be built from the archive extracted into
`/opt/kestrel/`. Windows builds should be built from from `C:\kestrel\`. This
is optional, but helps with future build reproducibility.

### Linux build
```
python3 build.py --system linux --test-arch amd64
```

### Debian Package

Requires a debian based distribution with access to cargo and rustc >=1.56

Tested on Ubuntu 20.04 and 22.04

It is a good idea to build in a clean VM or container.

Packages required: build-essential devscripts debhelper lintian bash-completion cargo

Tested using ubuntu 22.04

Using a source release, create a new directory and move the `.tar.gz`
file into it. Copy the `.tar.gz` as `kestrel-_x.x.x.orig.tar.gz`.
Inside of the extracted source package, run `debuild` to build
a debian package.

### Manpage Generation

Manpages are converted from markdown using pandoc

```
pandoc -s -t man -o kestrel.1 kestrel.1.md
```

### macOS build
Specifying arm64 or amd64 will run tests on the binary for
that architecture. If you're on an ARM mac use arm64 or amd64 if you're on
an intel mac
```
python3 build.py -s macos -t arm64
```

### Windows build
Specifying -w (--win-installer) will use Inno Setup to build the windows
installer

```
python3 build.py -s windows -t amd64 -w
```

### SHA256SUMS file
Create SHA-256 checksums of all of the .tar.gz, .zip, and .exe files in
the specified directory

```
python3 build.py -c build
```
