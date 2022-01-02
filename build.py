#!/usr/bin/env python3

# Copyright 2021-2022 Kyle Schreiber
# SPDX-License-Identifier: BSD-3-Clause

"""
Build Kestrel

Builds should be created from the source archives created with archive.py

OS Builds must be run on their respective systems
"""

import os
import argparse
import subprocess
from pathlib import Path
from shutil import copy2, make_archive


def main():
    parser = argparse.ArgumentParser(description="Build application")
    parser.add_argument("-t", "--target", type=str, choices=["linux", "macos", "windows"], help="Build for operating system")
    parser.add_argument("-c", "--checksum", type=str, metavar="RELEASE_DIR", nargs=1)

    args = parser.parse_args()

    if args.target:
        if args.target == "linux":
            build_linux()
        elif args.target == "macos":
            build_macos()
        elif args.target == "windows":
            build_windows()
        else:
            raise ValueError("OS support not implemented")
    elif args.checksum:
        release_loc = args.checksum
        calculate_checksums(release_loc)
    else:
        parser.print_help()


def build_linux():
    build_linux_target("x86_64-unknown-linux-musl", "amd64", "x86_64-linux-gnu-strip", make_build_dir=True, run_tests=True)
    build_linux_target("aarch64-unknown-linux-musl", "arm64", "aarch64-linux-gnu-strip")


def build_linux_target(target_arch, arch_tag, strip_prog_name, make_build_dir=False, run_tests=False):
    license_name = "LICENSE.txt"
    third_party_name = "THIRD-PARTY.txt"
    bin_name = "kestrel"

    if run_tests:
        print("Running tests for {}".format(target_arch))
        subprocess.run(["cargo", "test", "--release", "--workspace", "--target", target_arch])

    print("Building for {}".format(target_arch))
    subprocess.run(["cargo", "build", "--frozen", "--release", "--target", target_arch])
    source_version = read_version()
    if source_version == "":
        raise ValueError("Could not get version from Cargo.toml")

    archive_name = "kestrel-linux-v{}-{}".format(source_version, arch_tag)

    if make_build_dir:
        os.mkdir("build")

    package_path = Path("build", archive_name)
    os.mkdir(package_path)

    source_bin_path = Path("target", target_arch, "release", bin_name)
    target_bin_path = Path(package_path, bin_name)

    copy2(source_bin_path, target_bin_path)
    
    print("stripping binary")
    subprocess.run([strip_prog_name, str(target_bin_path)])

    copy2(Path(license_name), Path(package_path, license_name))
    copy2(Path(third_party_name), Path(package_path, third_party_name))

    print("creating tarball")
    create_tarball(archive_name)


def create_tarball(archive_name):
    make_archive(Path("build", archive_name), "gztar", root_dir="build", base_dir=archive_name)


def read_version():
    """ Read version info from Cargo.toml """
    source_version = ""

    with open("Cargo.toml", "r") as f:
        for line in f.readlines():
            check_line = line.strip()
            if check_line.startswith("version"):
                version = check_line.split("=")[1].strip().strip("\"")
                source_version = version
                break
    return source_version


def build_macos():
    print("Building for macos")

def build_windows():
    print("Building for windows")

def calculate_checksums(release_loc):
    print("Calculating SHA-256 hashes for loc", release_loc)


if __name__ == "__main__":
    main()
