$version = "0.11.0"

$buildTarget = "x86_64-pc-windows-msvc"
$packageDir = "kestrel-windows-v$version-x64"
$releaseDir = "release-windows-v$version"
$installerName = "kestrel-cli-setup-v$version-x64.exe"

function main($cliArgs) {
    $subcommand = $cliArgs[0]
    switch ($subcommand) {
        "build" { build }
        "package" {package }
        "installer" { installer }
        "all" { all }
        Default {
            "Command not found. Choose from [build, package, installer]"
            exit 1
        }
    }

    exit 0
}

function build {
    cargo build --release --target $buildTarget
}

function package {
    build
    delete-dir("build\$packageDir")
    create-dir("build")
    create-dir("build\$packageDir")
    Copy-Item "LICENSE.txt" -Destination "build\$packageDir"
    Copy-Item "THIRD-PARTY-LICENSE.txt" -Destination "build\$packageDir"
    Copy-Item "target\$buildTarget\release\kestrel.exe" -Destination "build\$packageDir\kestrel.exe"
    7z a "build\$packageDir.zip" "build\$packageDir"
}

function installer {
    build
    create-dir("build")
    Copy-Item "target\$buildTarget\release\kestrel.exe" -Destination "build\kestrel.exe"
    iscc setup.iss
}

function all {
    package
    installer
    create-dir("build")
    delete-dir("build\$releaseDir")
    create-dir("build\$releaseDir")
    Copy-Item "build\$packageDir.zip" -Destination "build\$releaseDir"
    Copy-Item "build\wininstaller\$installerName" -Destination "build\$releaseDir"
    7z a "build\$releaseDir.zip" "build\$releaseDir"
}

function create-dir($d) {
    if (!(Test-Path $d)) {
        $_tmp = New-Item -ItemType Directory -Path $d
    }
}

function delete-dir($d) {
    if (Test-Path $d) {
        Remove-Item -Force $d
    }
}

main($args)