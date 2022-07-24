#!/usr/bin/env python3

# Copyright 2021-2022 Kyle Schreiber
# SPDX-License-Identifier: BSD-3-Clause

"""
Build Kestrel

OS builds must be run on their respective systems
"""

import os
import sys
import stat
import argparse
import subprocess
import hashlib
import tarfile
from pathlib import Path
from shutil import copy2, make_archive, copytree, rmtree

def main():
    parser = argparse.ArgumentParser(description="Build application")
    parser.add_argument("--os", type=str, choices=["linux", "macos", "windows"], help="Build for operating system")
    parser.add_argument("-a", "--arch", type=str, choices=["amd64", "arm64"], action="append", help="CPU architecture")
    parser.add_argument("--test-arch", type=str, choices=["amd64", "arm64"], help="Run tests on CPU architecture")
    parser.add_argument("--checksum", type=str, metavar="RELEASE_DIR", help="Create SHA-256 checksum file")
    parser.add_argument("--win-installer", action="store_true", help="Create the windows installer")
    parser.add_argument("--source", action="store_true", help="Create source archive")
    parser.add_argument("--clean", action="store_true", help="Clean build directories")
    parser.add_argument("--deb", action="store_true", help="Build .deb package in container")
    parser.add_argument("--rpm", action="store_true", help="Build .rpm package in container")
    parser.add_argument("--docker", action="store_true", help="Use docker command instead of podman")

    args = parser.parse_args()

    if args.clean:
        clean_build()
    elif args.os:
        if len(args.arch) < 1 or len(args.arch) > 2:
            print_help(parser)
        if not args.test_arch:
            print_help(parser)
        cpus = args.arch
        test_arch = args.test_arch
        if args.os == "linux":
            build_linux(cpus, test_arch)
        elif args.os == "macos":
            build_macos(cpus, test_arch)
        elif args.os == "windows":
            if len(cpus) > 1 or cpus[0] != "amd64":
                print_help(parser)
            build_windows(cpus, test_arch, args.win_installer)
        else:
            raise ValueError("OS support not implemented")
    elif args.checksum:
        release_loc = args.checksum
        calculate_checksums(release_loc)
    elif args.source:
        build_source_archive()
    elif args.deb:
        cpus = args.arch
        if len(cpus) < 1:
            print_help(parser)
        use_podman = True
        if args.docker:
            use_podman = False
        build_deb(cpus, podman=use_podman)
    elif args.rpm:
        cpus = args.arch
        if len(cpus) < 1:
            print_help(parser)
        use_podman = True
        if args.docker:
            use_podman = False
        build_rpm(cpus, podman=use_podman)
    else:
        print_help(parser)

def print_help(parser):
    parser.print_help(file=sys.stderr)
    sys.exit(1)

def clean_build():
    rmtree("build", ignore_errors=True)
    rmtree("vendor", ignore_errors=True)
    rmtree("target", ignore_errors=True)

def build_source_archive():
    source_version = read_version()

    vendor_config = vendor_source()

    archive_name = "kestrel-{}".format(source_version)

    source_archive_path = Path("build", archive_name)

    copytree(Path("."), source_archive_path, ignore=ignore_files)

    # Check if the cargo config.toml is set up to use archived sources,
    # if not, write the archived sources config
    cargo_toml_path = Path(source_archive_path, ".cargo", "config.toml")
    write_config = True
    with open(cargo_toml_path, "r") as f:
        for line in f.readlines():
            if "[source.vendored-sources]" in line:
                write_config = False
                break

    if write_config:
        with open(cargo_toml_path, "a") as f:
            f.write(vendor_config)

    create_tarball(archive_name)

    rmtree(source_archive_path)

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

def check_arch_equals(arch, check):
    return arch == check

def build_linux(cpus, test_arch):
    os_tag = "linux"
    bin_name = "kestrel"

    source_version = read_version()

    run_tests = False
    if "amd64" in cpus:
        run_tests = check_arch_equals(test_arch, "amd64")
        build_target("x86_64-unknown-linux-musl", os_tag, source_version, "amd64", "x86_64-linux-gnu-strip", bin_name, run_tests=run_tests)
    if "arm64" in cpus:
        run_tests = check_arch_equals(test_arch, "arm64")
        env_var = {
            "RUSTFLAGS": "-C linker=aarch64-linux-gnu-gcc"
        }
        build_target("aarch64-unknown-linux-musl", os_tag, source_version, "arm64", "aarch64-linux-gnu-strip", bin_name, run_tests=run_tests, env_vars=env_var)

def build_macos(cpus, test_arch):
    os_tag = "macos"
    bin_name = "kestrel"

    source_version = read_version()

    run_tests = False
    if "amd64" in cpus:
        run_tests = check_arch_equals(test_arch, "amd64")
        build_target("x86_64-apple-darwin", os_tag, source_version, "amd64", "strip", bin_name, run_tests=run_tests)
    if "arm64" in cpus:
        run_tests = check_arch_equals(test_arch, "arm64")
        build_target("aarch64-apple-darwin", os_tag, source_version, "arm64", "strip", bin_name, run_tests=run_tests)

def build_windows(cpus, test_arch, create_installer):
    os_tag = "windows"
    bin_name = "kestrel.exe"
    arch_tag = "x64"

    source_version = read_version()

    run_tests = False
    if "amd64" in cpus:
        run_tests = check_arch_equals(test_arch, "amd64")
        build_target("x86_64-pc-windows-msvc", os_tag, source_version, arch_tag, None, bin_name, run_tests=run_tests, make_tarball=False)

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

def build_deb(cpus, podman=True):
    version = read_version()
    deb_rev = "1"
    if not Path("build", "kestrel-{}.tar.gz".format(version)).exists():
        build_source_archive()
    if "amd64" in cpus:
        build_deb_arch(version, "amd64", deb_rev, podman=podman)
    if "arm64" in cpus:
        build_deb_arch(version, "arm64", deb_rev, podman=podman)

def build_deb_arch(version, arch, deb_rev, podman=True):
    build_tool = "podman"
    if not podman:
        build_tool = "docker"
    docker_build = "{} build --platform=linux/{} --build-arg APP_VERSION={} -t kestrel-deb-{}:latest -f docker-deb .".format(build_tool, arch, version, arch).split(" ")
    docker_container = "{} container create --name kdeb-{} kestrel-deb-{}:latest".format(build_tool, arch, arch).split(" ")
    docker_cp = "{} cp kdeb-{}:/build/kestrel_{}-{}_{}.deb build/".format(build_tool, arch, version, deb_rev, arch).split(" ")
    docker_container_rm = "{} container rm kdeb-{}".format(build_tool, arch).split(" ")

    prv = subprocess.run(docker_build)
    prv.check_returncode()

    prv = subprocess.run(docker_container)
    prv.check_returncode()

    prv = subprocess.run(docker_cp)
    prv.check_returncode()

    prv = subprocess.run(docker_container_rm)
    prv.check_returncode()

def build_rpm(cpus, podman=True):
    version = read_version()
    rpm_rev = "1"
    if not Path("build", "kestrel-{}.tar.gz".format(version)).exists():
        build_source_archive()

    if "amd64" in cpus:
        build_rpm_arch(version, "amd64", rpm_rev, podman=podman)
    if "arm64" in cpus:
        build_rpm_arch(version, "arm64", rpm_rev, podman=podman)

def build_rpm_arch(version, arch, rpm_rev, podman=True):
    build_tool = "podman"
    if not podman:
        build_tool = "docker"

    alt_arch = ""
    if arch == "amd64":
        alt_arch = "x86_64"
    elif arch == "arm64":
        alt_arch = "aarch64"

    docker_build = "{} build --platform=linux/{} --build-arg APP_VERSION={} -t kestrel-rpm-{}:latest -f docker-rpm .".format(build_tool, arch, version, arch).split(" ")
    docker_container = "{} container create --name krpm-{} kestrel-rpm-{}:latest".format(build_tool, arch, arch).split(" ")
    docker_cp = "{} cp krpm-{}:/home/buildbot/rpmbuild/RPMS/{}/kestrel-{}-{}.fc36.{}.rpm build/".format(build_tool, arch, alt_arch, version, rpm_rev, alt_arch).split(" ")
    docker_container_rm = "{} container rm krpm-{}".format(build_tool, arch).split(" ")

    prv = subprocess.run(docker_build)
    prv.check_returncode()

    prv = subprocess.run(docker_container)
    prv.check_returncode()

    prv = subprocess.run(docker_cp)
    prv.check_returncode()

    prv = subprocess.run(docker_container_rm)
    prv.check_returncode()

def calculate_checksums(loc):
    """
    Write the SHA-256 hashes of files in the specified directory
    to a file called SHA256SUMS.txt in that directory
    """
    hashes = []

    loc = Path(loc)

    for path in loc.iterdir():
        path_name = path.name
        if (path_name.endswith(".tar.gz") or
            path_name.endswith(".zip") or
            path_name.endswith(".exe") or
            path_name.endswith(".deb")
        ):
            hash_data = calculate_hash(path)
            hashes.append(hash_data)

    hashes = sorted(hashes, key=lambda x: x[0])
    shasums_file = Path(loc, "SHA256SUMS.txt")
    with open(shasums_file, "w") as f:
        for hash_data in hashes:
            filename, hash_value = hash_data
            f.write("{}  {}\n".format(hash_value, filename))

def build_target(target_arch, os_tag, source_version, arch_tag, strip_prog_name, bin_name, run_tests=False, make_tarball=True, env_vars=None):
    license_name = "LICENSE.txt"
    third_party_name = "THIRD-PARTY-LICENSE.txt"

    if run_tests:
        print("Running tests for {}".format(target_arch))
        prv = subprocess.run(["cargo", "test", "--release", "--workspace", "--target", target_arch])
        prv.check_returncode()

    print("Building for {}".format(target_arch))
    if env_vars:
        os_env = os.environ.copy()
        env_vars = {**env_vars, **os_env}

    prv = subprocess.run(["cargo", "build", "--frozen", "--release", "--target", target_arch], env=env_vars)
    prv.check_returncode()

    archive_name = create_archive_name(os_tag, source_version, arch_tag)

    if not Path("build").exists():
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
    if os_tag != "windows":
        copytree(Path("docs", "man"), Path(package_path, "man"), dirs_exist_ok=True)
        copytree(Path("completion"), Path(package_path, "completion"), dirs_exist_ok=True)

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
        if tarinfo.mode & stat.S_IXUSR:
            tarinfo.mode = 0o755
        else:
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

    if source_version == "":
        raise RuntimeError("Could not get version from Cargo.toml")

    return source_version


if __name__ == "__main__":
    main()
