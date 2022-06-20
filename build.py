#!/usr/bin/env python3

# Copyright 2021-2022 Kyle Schreiber
# SPDX-License-Identifier: BSD-3-Clause

"""
Build Kestrel

OS builds must be run on their respective systems
"""

import os
import argparse
import subprocess
import hashlib
import tarfile
from pathlib import Path
from shutil import copy2, make_archive, copytree, rmtree

def main():
    parser = argparse.ArgumentParser(description="Build application")
    parser.add_argument("-s", "--system", type=str, choices=["linux", "macos", "windows"], help="Build for operating system")
    parser.add_argument("-t", "--test-arch", choices=["amd64", "arm64"], help="Run tests on architecture")
    parser.add_argument("-c", "--checksum", type=str, metavar="RELEASE_DIR", help="Create SHA-256 checksum file")
    parser.add_argument("-w", "--win-installer", action="store_true", help="Create the windows installer")
    parser.add_argument("-a", "--archive", action="store_true", help="Create source archive")
    parser.add_argument("--clean", action="store_true", help="Clean build directories")

    args = parser.parse_args()

    if args.clean:
        rmtree("build")
        rmtree("vendor")
    elif args.system:
        if args.system == "linux":
            build_linux(args.test_arch)
        elif args.system == "macos":
            build_macos(args.test_arch)
        elif args.system == "windows":
            if args.win_installer:
                build_windows(args.test_arch, create_installer=True)
            else:
                build_windows(args.test_arch)
        else:
            raise ValueError("OS support not implemented")
    elif args.checksum:
        release_loc = args.checksum
        calculate_checksums(release_loc)
    elif args.archive:
        build_archive()
    else:
        parser.print_help()

def build_archive():
    source_version = read_version()
    if source_version == "":
        raise ValueError("Could not get source version")

    vendor_config = vendor_source()

    archive_name = "kestrel-{}".format(source_version)

    source_archive_path = Path("build", archive_name)

    copytree(Path("."), source_archive_path, ignore=ignore_files)

    # Write the vendor crates configuration to .cargo/config.toml so that
    # builds will use the vendor folder
    cargo_toml_path = Path(source_archive_path, ".cargo", "config.toml")
    with open(cargo_toml_path, "a") as f:
        f.write(vendor_config)

    create_tarball(archive_name)

def vendor_source():
    vendor_output = subprocess.run(["cargo", "vendor", "--versioned-dirs", "--locked"], capture_output=True)
    vendor_output.check_returncode()
    vendor_config = vendor_output.stdout.decode("utf-8")

    return vendor_config

def ignore_files(path, names):
    ignored_dirs = [
        (Path("."), [".git", "target", "build"]),
        (Path("windows"), ["install", "output"])
    ]

    for ignored_dir in ignored_dirs:
        dir_path, subdir_list = ignored_dir
        if str(Path(path)) == str(dir_path):
            return subdir_list

    return []

def build_linux(test_arch):
    os_tag = "linux"
    bin_name = "kestrel"

    source_version = read_version()
    if source_version == "":
        raise ValueError("Could not get version from Cargo.toml")

    amd64_test, arm64_test = check_test_arch(test_arch)

    build_target("x86_64-unknown-linux-musl", os_tag, source_version, "amd64", "x86_64-linux-gnu-strip", bin_name, make_build_dir=True, run_tests=amd64_test)
    build_target("aarch64-unknown-linux-musl", os_tag, source_version, "arm64", "aarch64-linux-gnu-strip", bin_name, run_tests=arm64_test)

def build_macos(test_arch):
    os_tag = "macos"
    bin_name = "kestrel"

    source_version = read_version()
    if source_version == "":
        raise ValueError("Could not get version from Cargo.toml")

    amd64_test, arm64_test = check_test_arch(test_arch)

    build_target("aarch64-apple-darwin", os_tag, source_version, "arm64", "strip", bin_name, make_build_dir=True, run_tests=arm64_test)
    build_target("x86_64-apple-darwin", os_tag, source_version, "amd64", "strip", bin_name, run_tests=amd64_test)

def build_windows(test_arch, create_installer=False):
    os_tag = "windows"
    bin_name = "kestrel.exe"
    arch_tag = "x64"

    source_version = read_version()
    if source_version == "":
        raise ValueError("Could not get version from Cargo.toml")

    amd64_test, arm64_test = check_test_arch(test_arch)

    build_target("x86_64-pc-windows-msvc", os_tag, source_version, arch_tag, None, bin_name, make_build_dir=True, run_tests=amd64_test, make_tarball=False)

    if create_installer:
        archive_name = create_archive_name(os_tag, source_version, arch_tag)
        archive_path = Path("build", archive_name)
        create_windows_installer(archive_path, bin_name)

def create_windows_installer(archive_path, bin_name):
    license_name = "LICENSE.txt"
    third_party_name = "THIRD-PARTY-LICENSE.txt"

    install_dir = Path("windows", "install")
    install_dir.mkdir()
    output_dir = Path("windows", "output")
    output_dir.mkdir()
    install_bin_dir = Path(install_dir, "bin")
    install_bin_dir.mkdir()

    copy2(Path(archive_path, bin_name), install_bin_dir)
    copy2(Path(archive_path, license_name), install_dir)
    copy2(Path(archive_path, third_party_name), install_dir)

    setup_script_path = Path("windows", "setup.iss")
    prv = subprocess.run(["iscc.exe", str(setup_script_path)])
    prv.check_returncode()

    installer_bin = sorted(output_dir.glob("*.exe"))[0]
    copy2(installer_bin, Path("build"))

def calculate_checksums(loc):
    """
    Write the SHA-256 hashes of all .tar.gz, .zip, and .exe files in the
    specified directory to a file called SHA256SUMS.txt in that directory
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
            elif ext2 == ".exe":
                hash_data = calculate_hash(path)
                hashes.append(hash_data)
            else:
                ext1 = path_exts.pop()
                if ext1 == ".tar" and ext2 == ".gz":
                    hash_data = calculate_hash(path)
                    hashes.append(hash_data)

    hashes = sorted(hashes, key=lambda x: x[0])
    shasums_file = Path(loc, "SHA256SUMS.txt")
    with open(shasums_file, "w") as f:
        for hash_data in hashes:
            filename, hash_value = hash_data
            f.write("{}  {}\n".format(hash_value, filename))

def build_target(target_arch, os_tag, source_version, arch_tag, strip_prog_name, bin_name, make_build_dir=False, run_tests=False, make_tarball=True):
    license_name = "LICENSE.txt"
    third_party_name = "THIRD-PARTY-LICENSE.txt"

    if run_tests:
        print("Running tests for {}".format(target_arch))
        prv = subprocess.run(["cargo", "test", "--release", "--workspace", "--target", target_arch])
        prv.check_returncode()

    print("Building for {}".format(target_arch))
    prv = subprocess.run(["cargo", "build", "--frozen", "--release", "--target", target_arch])
    prv.check_returncode()

    archive_name = create_archive_name(os_tag, source_version, arch_tag)

    if make_build_dir:
        os.mkdir("build")

    package_path = Path("build", archive_name)
    os.mkdir(package_path)

    source_bin_path = Path("target", target_arch, "release", bin_name)
    target_bin_path = Path(package_path, bin_name)

    copy2(source_bin_path, target_bin_path)

    if strip_prog_name:
        print("stripping binary")
        prv = subprocess.run([strip_prog_name, str(target_bin_path)])
        prv.check_returncode()

    copy2(Path(license_name), Path(package_path, license_name))
    copy2(Path(third_party_name), Path(package_path, third_party_name))

    if make_tarball:
        print("creating tarball")
        create_tarball(archive_name)
    else:
        print("creating zip")
        create_zip(archive_name)

def create_archive_name(os_tag, source_version, arch_tag):
    return "kestrel-{}-v{}-{}".format(os_tag, source_version, arch_tag)

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
    orig_dir = os.getcwd()
    os.chdir("build")
    with tarfile.open("{}.tar.gz".format(archive_name), "w:gz") as archive:
        archive.add(archive_name, filter=change_perms)
    os.chdir(orig_dir)

def change_perms(tarinfo):
    tarinfo.uid = 0
    tarinfo.gid = 0
    if tarinfo.isfile():
        tarinfo.mode = 0o644
    elif tarinfo.isdir():
        tarinfo.mode = 0o755

    return tarinfo

def create_zip(archive_name):
    make_archive(Path("build", archive_name), "zip", root_dir="build", base_dir=archive_name)

def read_version():
    """ Read version info from Cargo.toml """
    source_version = ""

    with open("src/cli/Cargo.toml", "r") as f:
        for line in f.readlines():
            check_line = line.strip()
            if check_line.startswith("version"):
                version = check_line.split("=")[1].strip().strip("\"")
                source_version = version
                break
    return source_version


if __name__ == "__main__":
    main()
