#!/usr/bin/env python3

# Copyright 2021-2022 Kyle Schreiber
# SPDX-License-Identifier: BSD-3-Clause


"""
Create a tarball of the source
"""

import sys
import os
import subprocess
import tarfile

from shutil import copy2, copytree, make_archive
from pathlib import Path

def main():
    source_version = read_version()
    if source_version == "":
        raise ValueError("Could not get version from Cargo.toml")

    archive_name = "kestrel-source-v{}".format(source_version)

    file_list = [
        ("Cargo.lock", "Cargo.lock"),
        ("Cargo.toml", "Cargo.toml"),
        ("README.md", "README.md"),
        ("LICENSE.txt", "LICENSE.txt"),
        ("THIRD-PARTY.txt", "THIRD-PARTY.txt"),
        ("CHANGELOG.md", "CHANGELOG.md"),
        ("BUILDING.md", "BUILDING.md"),
        ("archive.py", "archive.py"),
        ("build.py", "build.py"),
        (".gitignore", ".gitignore"),
    ]

    dir_list = [
        ("src", "src"),
        ("tests", "tests"),
        ("crypto", "crypto"),
        ("docs", "docs"),
        ("vendor", "vendor"),
        ("packaging", "packaging"),
    ]

    os.mkdir("archive")
    vendor_source()

    create_source_directory(archive_name, file_list, dir_list)
    create_tarball(archive_name)

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

def vendor_source():
    vendor_output = subprocess.run(["cargo", "vendor", "--versioned-dirs", "--locked"], capture_output=True)
    vendor_output.check_returncode()
    vendor_config = vendor_output.stdout.decode("utf-8")

    vendor_config_path = Path("archive", "config.toml")
    copy2(Path(".cargo", "config.toml"), vendor_config_path)

    # configure cargo.toml to use vendored sources
    with open(vendor_config_path, "a") as f:
        f.write(vendor_config)

def create_source_directory(archive_name, file_list, dir_list):
    os.mkdir(Path("archive", archive_name))
    archive_path = Path("archive", archive_name)
    os.mkdir(Path("archive", archive_name, ".cargo"))
    copy2(Path("archive", "config.toml"), Path("archive", archive_name, ".cargo", "config.toml"))
    os.remove(Path("archive", "config.toml"))

    for f in file_list:
        src, dest = f
        final_dest = archive_path / dest
        copy2(src, final_dest)

    for d in dir_list:
        src, dest = d
        final_dest = archive_path / dest
        copytree(src, final_dest)


def create_tarball(archive_name):
    # .tar.gz is appended
    make_archive(Path("archive", archive_name), "gztar", root_dir="archive", base_dir=archive_name)

if __name__ == "__main__":
    main()
