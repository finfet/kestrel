#!/usr/bin/env python3

"""
Create a tarball and zip of the source
"""

import sys
import os
import subprocess
import tarfile
import zipfile

from shutil import copy2, copytree, make_archive
from pathlib import Path

def main():
    if len(sys.argv) < 2:
        print("Supply a version", file=sys.stderr)
        sys.exit(1)
    
    tag_name = sys.argv[1]
    archive_name = "kestrel-source-{}".format(tag_name)

    file_list = [
        ("Cargo.lock", "Cargo.lock"),
        ("Cargo.toml", "Cargo.toml"),
        ("README.md", "README.txt"),
        ("LICENSE.txt", "LICENSE.txt"),
        ("NOTICE.txt", "NOTICE.txt"),
        ("THIRD-PARTY.txt", "THIRD-PARTY.txt"),
        ("CHANGELOG.md", "CHANGELOG.txt"),
    ]

    dir_list = [
        ("src", "src"),
        ("crypto", "crypto"),
        ("docs", "docs"),
        ("vendor", "vendor"),
    ]

    os.mkdir("archive")
    vendor_source()

    create_source_directory(archive_name, file_list, dir_list)
    create_tarball(archive_name)
    create_zipfile(archive_name)


def vendor_source():
    vendor_output = subprocess.run(["cargo", "vendor", "--locked"], capture_output=True)
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
    os.chdir(Path("archive"))
    # .tar.gz is appended
    make_archive(archive_name, "gztar", root_dir=None, base_dir=archive_name)
    os.chdir("..")

def create_zipfile(archive_name):
    os.chdir(Path("archive"))
    # .zip is appended
    make_archive(archive_name, "zip", root_dir=None, base_dir=archive_name)
    os.chdir("..")

if __name__ == "__main__":
    main()