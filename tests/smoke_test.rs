use std::process::{Command, Stdio};
use std::path::PathBuf;
use std::io::Write;

static EXE_LOC: &'static str = env!("CARGO_BIN_EXE_kestrel");

#[test]
fn test_key_gen() {
    let temp_dir = std::env::temp_dir();
    let mut key_file_loc = PathBuf::new();
    key_file_loc.push(temp_dir);
    key_file_loc.push("keys.txt");

    let mut app = Command::new(EXE_LOC)
        .arg("key")
        .arg("generate")
        .arg("-o")
        .arg(key_file_loc.as_path().as_os_str())
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    
    let mut stdin = app.stdin.take().unwrap();
    // Rust docs reccommend running write in a separate thread.
    std::thread::spawn(move || {
        stdin.write_all("joe\njoepass\njoepass\n".as_bytes()).unwrap();
    });

    let output = app.wait_with_output().unwrap();

    std::fs::remove_file(key_file_loc).unwrap();

    assert!(output.status.success());

    let stderr_output = String::from_utf8(output.stderr.clone()).unwrap();
    let stderr_lines = stderr_output.lines().map(|l| l.to_string()).collect::<Vec<String>>();
    assert_eq!(stderr_lines.len(), 3);
    assert_eq!("Key name: ", stderr_lines[0]);
    assert_eq!("New password: ", stderr_lines[1]);
    assert_eq!("Confirm password: ", stderr_lines[2]);
}


#[test]
fn test_key_change_pass() {
    let alice_private = "AAG0rhkawzo/HQgNkV0TVJcK+p4WMgXy/KPNDpASrmiRXoCqG6yJvzOAv0zyxcaQQe7nYG2GtRxcWuo15u1Q69k+";

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
    let stdout_lines = stdout_output.lines().map(|l| l.to_string()).collect::<Vec<String>>();
    let stderr_lines = stderr_output.lines().map(|l| l.to_string()).collect::<Vec<String>>();

    assert_eq!(stderr_lines.len(), 2);
    assert_eq!(stdout_lines.len(), 1);

    assert_eq!("Old password: ", stderr_lines[0]);
    assert_eq!("New password: ", stderr_lines[1]);

    assert_eq!(stdout_lines[0].len(), 101);
}
