// Copyright The Kestrel Contributors
// SPDX-License-Identifier: BSD-3-Clause

use kestrel_crypto::secure_random;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

static EXE_LOC: &'static str = env!("CARGO_BIN_EXE_kestrel");

struct TempFile(PathBuf);

#[allow(dead_code)]
impl TempFile {
    /// Generate a random filename in the specified directory.
    /// Defaults to the system temporary directory if not providied.
    fn new() -> Self {
        TempFile::gen_tempfile(None::<&str>)
    }

    fn new_path<T: AsRef<Path>>(tempdir: T) -> Self {
        TempFile::gen_tempfile(Some(tempdir))
    }

    fn gen_tempfile<T: AsRef<Path>>(tempdir: Option<T>) -> Self {
        let suffix = hex::encode(secure_random(12).as_slice());
        let mut path = PathBuf::new();
        if let Some(d) = tempdir {
            path.push(d);
        } else {
            path.push(std::env::temp_dir())
        }
        path.push(format!("temp-{}.tmp", suffix));
        Self(path)
    }

    fn as_path(&self) -> &Path {
        self.0.as_path()
    }
}

impl Drop for TempFile {
    fn drop(&mut self) {
        match std::fs::remove_file(self.as_path()) {
            Ok(_) => {}
            Err(e) => eprintln!("Could not remove file: {}", e),
        }
    }
}

#[test]
fn test_key_gen() {
    let keyfile = TempFile::new_path("tests");

    let mut app = Command::new(EXE_LOC)
        .arg("key")
        .arg("generate")
        .arg("-o")
        .arg(keyfile.as_path())
        .arg("--env-pass")
        .env("KESTREL_PASSWORD", "joepass")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    let mut stdin = app.stdin.take().unwrap();
    // Rust docs reccommend running write in a separate thread.
    std::thread::spawn(move || {
        stdin.write_all("joe\n".as_bytes()).unwrap();
    });

    let output = app.wait_with_output().unwrap();

    assert!(output.status.success());

    let stderr_output = String::from_utf8(output.stderr.clone()).unwrap();
    let stderr_lines = stderr_output
        .lines()
        .map(|l| l.to_string())
        .collect::<Vec<String>>();
    assert_eq!(stderr_lines.len(), 1);
    assert_eq!("Key name: ", stderr_lines[0]);
}

#[test]
fn test_key_change_pass() {
    let alice_private =
        "ZWdrMPEp09tKN3rAutCDQTshrNqoh0MLPnEERRCm5KFxvXcTo+s/Sf2ze0fKebVsQilImvLzfIHRcJuX8kGetyAQL1VchvzHR28vFhdKeq+NY2KT";

    let app = Command::new(EXE_LOC)
        .arg("key")
        .arg("change-pass")
        .arg(alice_private)
        .arg("--env-pass")
        .env("KESTREL_PASSWORD", "alice")
        .env("KESTREL_NEW_PASSWORD", "alicenew")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    let output = app.wait_with_output().unwrap();

    assert!(output.status.success());

    let stdout_output = String::from_utf8(output.stdout.clone()).unwrap();
    let stderr_output = String::from_utf8(output.stderr.clone()).unwrap();
    let stdout_lines = stdout_output
        .lines()
        .map(|l| l.to_string())
        .collect::<Vec<String>>();
    let stderr_lines = stderr_output
        .lines()
        .map(|l| l.to_string())
        .collect::<Vec<String>>();

    assert_eq!(stderr_lines.len(), 0);
    assert_eq!(stdout_lines.len(), 1);
    assert_eq!(stdout_lines[0].len(), 125);
}

#[test]
fn test_key_extract_pub() {
    let alice_private =
        "ZWdrMPEp09tKN3rAutCDQTshrNqoh0MLPnEERRCm5KFxvXcTo+s/Sf2ze0fKebVsQilImvLzfIHRcJuX8kGetyAQL1VchvzHR28vFhdKeq+NY2KT";
    let expected_stdout = "PublicKey = D7ZZstGYF6okKKEV2rwoUza/tK3iUa8IMY+l5tuirmzzkEog";

    let app = Command::new(EXE_LOC)
        .arg("key")
        .arg("extract-pub")
        .arg(alice_private)
        .arg("--env-pass")
        .env("KESTREL_PASSWORD", "alice")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    let output = app.wait_with_output().unwrap();

    assert!(output.status.success());

    let stdout_output = String::from_utf8(output.stdout.clone()).unwrap();
    let stderr_output = String::from_utf8(output.stderr.clone()).unwrap();
    let stdout_lines = stdout_output
        .lines()
        .map(|l| l.to_string())
        .collect::<Vec<String>>();
    let stderr_lines = stderr_output
        .lines()
        .map(|l| l.to_string())
        .collect::<Vec<String>>();

    assert_eq!(stderr_lines.len(), 0);
    assert_eq!(stdout_lines.len(), 1);
    assert_eq!(expected_stdout, stdout_lines[0]);
}

#[test]
fn test_encrypt() {
    let plaintext = Path::new("tests/data.txt");
    let keyring = Path::new("tests/keyring.txt");
    let ciphertext = TempFile::new_path("tests");

    let app = Command::new(EXE_LOC)
        .arg("encrypt")
        .arg(plaintext.as_os_str())
        .arg("--to")
        .arg("bob")
        .arg("--from")
        .arg("alice")
        .arg("--output")
        .arg(ciphertext.as_path())
        .arg("--keyring")
        .arg(keyring.as_os_str())
        .arg("--env-pass")
        .env("KESTREL_PASSWORD", "alice")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    let output = app.wait_with_output().unwrap();

    assert!(output.status.success());

    let stderr_output = String::from_utf8(output.stderr.clone()).unwrap();
    let stderr_lines = stderr_output
        .lines()
        .map(|l| l.to_string())
        .collect::<Vec<String>>();

    assert_eq!(stderr_lines.len(), 1);
    assert_eq!("Encrypting...done", stderr_lines[0]);
}

#[test]
fn test_decrypt() {
    let keyring = Path::new("tests/keyring.txt");
    let ciphertext = Path::new("tests/data.txt.ktl");
    let plaintext = TempFile::new_path("tests");

    let app = Command::new(EXE_LOC)
        .arg("decrypt")
        .arg(ciphertext.as_os_str())
        .arg("-t")
        .arg("bob")
        .arg("-o")
        .arg(plaintext.as_path())
        .arg("-k")
        .arg(keyring.as_os_str())
        .arg("--env-pass")
        .env("KESTREL_PASSWORD", "bob")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    let output = app.wait_with_output().unwrap();

    assert!(output.status.success());

    let stdout_output = String::from_utf8(output.stdout.clone()).unwrap();
    let stderr_output = String::from_utf8(output.stderr.clone()).unwrap();
    let stdout_lines = stdout_output
        .lines()
        .map(|l| l.to_string())
        .collect::<Vec<String>>();
    let stderr_lines = stderr_output
        .lines()
        .map(|l| l.to_string())
        .collect::<Vec<String>>();

    assert_eq!(stdout_lines.len(), 0);
    assert_eq!(stderr_lines.len(), 2);

    assert_eq!("Decrypting...done", stderr_lines[0]);
    assert_eq!("Success. File from: alice", stderr_lines[1]);
}

#[test]
fn test_pass_encrypt() {
    let plaintext = Path::new("tests/data.txt");
    let ciphertext = TempFile::new_path("tests");

    let app = Command::new(EXE_LOC)
        .arg("password")
        .arg("encrypt")
        .arg(plaintext.as_os_str())
        .arg("-o")
        .arg(ciphertext.as_path())
        .arg("--env-pass")
        .env("KESTREL_PASSWORD", "pass123")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    let output = app.wait_with_output().unwrap();

    assert!(output.status.success());

    let stderr_output = String::from_utf8(output.stderr.clone()).unwrap();
    let stderr_lines = stderr_output
        .lines()
        .map(|l| l.to_string())
        .collect::<Vec<String>>();

    assert_eq!(stderr_lines.len(), 1);

    assert_eq!("Encrypting...done", stderr_lines[0]);
}

#[test]
fn test_pass_decrypt() {
    let ciphertext = Path::new("tests/pdata.txt.ktl");
    let plaintext = TempFile::new_path("tests");

    let app = Command::new(EXE_LOC)
        .arg("pass")
        .arg("dec")
        .arg(ciphertext.as_os_str())
        .arg("-o")
        .arg(plaintext.as_path())
        .arg("--env-pass")
        .env("KESTREL_PASSWORD", "pass123")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    let output = app.wait_with_output().unwrap();

    assert!(output.status.success());

    let stderr_output = String::from_utf8(output.stderr.clone()).unwrap();
    let stderr_lines = stderr_output
        .lines()
        .map(|l| l.to_string())
        .collect::<Vec<String>>();

    assert_eq!(stderr_lines.len(), 1);

    assert_eq!("Decrypting...done", stderr_lines[0]);
}
