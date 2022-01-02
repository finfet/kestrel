# Build Instructions

## Required Software

rustc 1.56+, cargo, and python3 for the build script.

Running the build steps manually without the python script is also
possible, but is more laborious)

- Linux
  - cargo targets: x86_64-unknown-linux-musl, aarch64-unknown-linux-musl
  - gcc aarch64 linker: on debian: gcc-aarch64-linux-gnu
- macOS
  - Xcode with command line tools
  - cargo targets: x86_64-apple-darwin, aarch64-apple-darwin
- Windows
  - Visual studio with MSVC toolchain
  - cargo targets: x86_64-pc-windows-msvc
  - Inno Setup 6.2+ for the windows installer

## Building

Build from a source release created with archive.py

Linux builds are built from /opt/kestrel/. This is optional, but helps with
future reproducible builds.

./build.py --target <linux|macos|windows>
./build.py --checksum <release-dir>