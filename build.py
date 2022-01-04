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
import hashlib
from pathlib import Path
from shutil import copy2, make_archive


def main():
    parser = argparse.ArgumentParser(description="Build application")
    parser.add_argument("-s", "--system", type=str, choices=["linux", "macos", "windows"], help="Build for operating system")
    parser.add_argument("-t", "--test-arch", choices=["amd64", "arm64"], help="Run tests on architecture")
    parser.add_argument("-c", "--checksum", type=str, metavar="RELEASE_DIR", help="Create SHA-256 checksum file")

    args = parser.parse_args()

    if args.system:
        if args.system == "linux":
            build_linux(args.test_arch)
        elif args.system == "macos":
            build_macos(args.test_arch)
        elif args.system == "windows":
            build_windows(args.test_arch)
        else:
            raise ValueError("OS support not implemented")
    elif args.checksum:
        release_loc = args.checksum
        calculate_checksums(release_loc)
    else:
        parser.print_help()

def build_linux(test_arch):
    os_tag = "linux"
    bin_name = "kestrel"

    amd64_test, arm64_test = check_test_arch(test_arch)

    build_target("x86_64-unknown-linux-musl", os_tag, "amd64", "x86_64-linux-gnu-strip", bin_name, make_build_dir=True, run_tests=amd64_test)
    build_target("aarch64-unknown-linux-musl", os_tag, "arm64", "aarch64-linux-gnu-strip", bin_name, run_tests=arm64_test)

def build_macos(test_arch):
    os_tag = "macos"
    bin_name = "kestrel"

    amd64_test, arm64_test = check_test_arch(test_arch)

    build_target("aarch64-apple-darwin", os_tag, "arm64", "strip", bin_name, make_build_dir=True, run_tests=arm64_test)
    build_target("x86_64-apple-darwin", os_tag, "amd64", "strip", bin_name, run_tests=amd64_test)

def build_windows(test_arch):
    print("Building for windows")

def calculate_checksums(loc):
    """
    Write the SHA-256 hashes of all .tar.gz and .zip files in the specified
    directory to a file called SHA256SUMS in that directory
    """
    hashes = []

    loc = Path(loc)

    for path in loc.iterdir():
        path_exts = path.suffixes
        if len(path_exts) == 1 and ".zip" in path_exts:
            calculate_hash(path)
            hashes.append(hash_data)
        elif len(path_exts) >= 2:
            ext2 = path_exts.pop()
            if ext2 == ".zip":
                hash_data = calculate_hash(path)
                hashes.append(hash_data)
            else:
                ext1 = path_exts.pop()
                if ext1 == ".tar" and ext2 == ".gz":
                    hash_data = calculate_hash(path)
                    hashes.append(hash_data)

    hashes = sorted(hashes, key=lambda x: x[0])
    shasums_file = Path(loc, "SHA256SUMS")
    with open(shasums_file, "w") as f:
        for hash_data in hashes:
            filename, hash_value = hash_data
            f.write("{} {}\n".format(filename, hash_value))

def build_target(target_arch, os_tag, arch_tag, strip_prog_name, bin_name, make_build_dir=False, run_tests=False):
    license_name = "LICENSE.txt"
    third_party_name = "THIRD-PARTY.txt"

    if run_tests:
        print("Running tests for {}".format(target_arch))
        prv = subprocess.run(["cargo", "test", "--release", "--workspace", "--target", target_arch])
        prv.check_returncode()

    print("Building for {}".format(target_arch))
    prv = subprocess.run(["cargo", "build", "--frozen", "--release", "--target", target_arch])
    prv.check_returncode()

    source_version = read_version()
    if source_version == "":
        raise ValueError("Could not get version from Cargo.toml")

    archive_name = "kestrel-{}-v{}-{}".format(os_tag, source_version, arch_tag)

    if make_build_dir:
        os.mkdir("build")

    package_path = Path("build", archive_name)
    os.mkdir(package_path)

    source_bin_path = Path("target", target_arch, "release", bin_name)
    target_bin_path = Path(package_path, bin_name)

    copy2(source_bin_path, target_bin_path)

    print("stripping binary")
    prv = subprocess.run([strip_prog_name, str(target_bin_path)])
    prv.check_returncode()

    copy2(Path(license_name), Path(package_path, license_name))
    copy2(Path(third_party_name), Path(package_path, third_party_name))

    print("creating tarball")
    create_tarball(archive_name)

def calculate_hash(loc):
    filename = loc.name
    hasher = hashlib.sha256()
    with open(loc, "rb") as f:
        while True:
            file_data = f.read(16384)
            if not file_data:
                break
            hasher.update(file_data)

    return (filename, hasher.hexdigest())

def check_test_arch(test_arch):
    """ Bool amd64, arm64 if test_arch equal to given arch """
    if not test_arch:
        return False, False

    if test_arch == "amd64":
        return True, False
    elif test_arch == "arm64":
        return False, True
    else:
        return False, False

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


if __name__ == "__main__":
    main()
