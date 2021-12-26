use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

static EXE_LOC: &'static str = env!("CARGO_BIN_EXE_kestrel");

#[test]
fn test_key_gen() {
    let mut key_file_loc = PathBuf::new();
    key_file_loc.push("tests");
    key_file_loc.push("tmp_keys.txt");

    let mut app = Command::new(EXE_LOC)
        .arg("key")
        .arg("generate")
        .arg("-o")
        .arg(key_file_loc.as_os_str())
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    let mut stdin = app.stdin.take().unwrap();
    // Rust docs reccommend running write in a separate thread.
    std::thread::spawn(move || {
        stdin
            .write_all("joe\njoepass\njoepass\n".as_bytes())
            .unwrap();
    });

    let output = app.wait_with_output().unwrap();

    std::fs::remove_file(key_file_loc).unwrap();

    assert!(output.status.success());

    let stderr_output = String::from_utf8(output.stderr.clone()).unwrap();
    let stderr_lines = stderr_output
        .lines()
        .map(|l| l.to_string())
        .collect::<Vec<String>>();
    assert_eq!(stderr_lines.len(), 3);
    assert_eq!("Key name: ", stderr_lines[0]);
    assert_eq!("New password: ", stderr_lines[1]);
    assert_eq!("Confirm password: ", stderr_lines[2]);
}

#[test]
fn test_key_change_pass() {
    let alice_private =
        "AAG0rhkawzo/HQgNkV0TVJcK+p4WMgXy/KPNDpASrmiRXoCqG6yJvzOAv0zyxcaQQe7nYG2GtRxcWuo15u1Q69k+";

    let mut app = Command::new(EXE_LOC)
        .arg("key")
        .arg("change-pass")
        .arg(alice_private)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    let mut stdin = app.stdin.take().unwrap();
    std::thread::spawn(move || {
        stdin.write_all("alicepass\nalicenew\n".as_bytes()).unwrap();
    });

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

    assert_eq!(stderr_lines.len(), 2);
    assert_eq!(stdout_lines.len(), 1);

    assert_eq!("Old password: ", stderr_lines[0]);
    assert_eq!("New password: ", stderr_lines[1]);

    assert_eq!(stdout_lines[0].len(), 101);
}

#[test]
fn test_key_extract_pub() {
    let alice_private =
        "AAG0rhkawzo/HQgNkV0TVJcK+p4WMgXy/KPNDpASrmiRXoCqG6yJvzOAv0zyxcaQQe7nYG2GtRxcWuo15u1Q69k+";
    let expected_stdout = "PublicKey = bJMx+URyEwCKSYYPDyVwRrVhiAu2MJSSxG/NC8l570DojWkm";

    let mut app = Command::new(EXE_LOC)
        .arg("key")
        .arg("extract-pub")
        .arg(alice_private)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    let mut stdin = app.stdin.take().unwrap();
    std::thread::spawn(move || {
        stdin.write_all("alicepass\n".as_bytes()).unwrap();
    });

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

    assert_eq!(stderr_lines.len(), 1);
    assert_eq!(stdout_lines.len(), 1);

    assert_eq!("Password: ", stderr_lines[0]);

    assert_eq!(expected_stdout, stdout_lines[0]);
}

#[test]
fn test_encrypt() {
    let mut keyring_loc = PathBuf::new();
    keyring_loc.push("tests");
    keyring_loc.push("keyring.txt");

    let mut ciphertext_loc = PathBuf::new();
    ciphertext_loc.push("tests");
    ciphertext_loc.push("data_tmp.txt.ktl");

    let mut app = Command::new(EXE_LOC)
        .arg("encrypt")
        .arg(keyring_loc.as_os_str())
        .arg("--to")
        .arg("bob")
        .arg("--from")
        .arg("alice")
        .arg("--output")
        .arg(ciphertext_loc.as_os_str())
        .arg("--keyring")
        .arg(keyring_loc.as_os_str())
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    let mut stdin = app.stdin.take().unwrap();
    std::thread::spawn(move || {
        stdin.write_all("alicepasss\n".as_bytes()).unwrap();
    });

    let output = app.wait_with_output().unwrap();

    std::fs::remove_file(ciphertext_loc).unwrap();

    assert!(output.status.success());

    let stderr_output = String::from_utf8(output.stderr.clone()).unwrap();
    let stderr_lines = stderr_output
        .lines()
        .map(|l| l.to_string())
        .collect::<Vec<String>>();

    assert_eq!(stderr_lines.len(), 2);

    assert_eq!("Unlock 'alice' key: ", stderr_lines[0]);
    assert_eq!("Encrypting...done", stderr_lines[1]);
}
