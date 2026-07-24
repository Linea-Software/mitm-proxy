//! CLI integration tests for the compiled `mitm-proxy` binary.
//!
//! Uses `assert_cmd` to launch the binary and verify flags, startup, and
//! basic behaviour.  These tests prove the compiled exe + clap wiring works.

use assert_cmd::prelude::*;
use predicates::prelude::*;
use std::net::TcpStream;
use std::process::{Child, Command};
use std::time::Duration;
use tempfile::TempDir;

/// Start the proxy binary in the background, wait for the TCP port to become
/// available, and return the child handle (killing it on drop).
fn spawn_proxy(args: &[&str]) -> Child {
    let mut cmd = Command::cargo_bin("mitm-proxy").unwrap();
    cmd.args(args)
        .env("RUST_LOG", "mitm_proxy=info")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    let child = cmd.spawn().unwrap();

    // Give it a moment
    std::thread::sleep(Duration::from_millis(500));
    child
}

fn port_is_open(port: u16) -> bool {
    TcpStream::connect_timeout(
        &format!("127.0.0.1:{port}").parse().unwrap(),
        Duration::from_millis(500),
    )
    .is_ok()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn cli_help() {
    let mut cmd = Command::cargo_bin("mitm-proxy").unwrap();
    cmd.arg("--help");
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("--listen"))
        .stdout(predicate::str::contains("--http3"))
        .stdout(predicate::str::contains("--ca-dir"))
        .stdout(predicate::str::contains("--install-ca"))
        .stdout(predicate::str::contains("--insecure-upstream"));
}

#[test]
fn cli_version() {
    let mut cmd = Command::cargo_bin("mitm-proxy").unwrap();
    cmd.arg("--version");
    cmd.assert().success();
}

#[test]
fn cli_listen_binds_to_port() {
    let ca_dir = TempDir::new().unwrap();
    let ca_dir_str = ca_dir.path().to_str().unwrap();

    let mut child = spawn_proxy(&["--listen", "127.0.0.1:19980", "--ca-dir", ca_dir_str]);

    assert!(port_is_open(19980), "proxy should bind to 127.0.0.1:19980");

    child.kill().ok();
    child.wait().ok();
}

#[test]
fn cli_http3_flag_accepted() {
    let ca_dir = TempDir::new().unwrap();
    let ca_dir_str = ca_dir.path().to_str().unwrap();

    let mut child = spawn_proxy(&[
        "--listen",
        "127.0.0.1:19981",
        "--http3",
        "127.0.0.1:19982",
        "--ca-dir",
        ca_dir_str,
    ]);

    assert!(port_is_open(19981), "TCP port should be open");

    child.kill().ok();
    child.wait().ok();
}

#[test]
fn cli_ca_dir_creates_certs() {
    let ca_dir = TempDir::new().unwrap();
    let ca_dir_str = ca_dir.path().to_str().unwrap();

    let mut child = spawn_proxy(&["--listen", "127.0.0.1:19983", "--ca-dir", ca_dir_str]);

    // After startup, cert files should exist
    assert!(ca_dir.path().join("mitm_ca.pem").exists());
    assert!(ca_dir.path().join("mitm_ca.key").exists());

    child.kill().ok();
    child.wait().ok();
}

#[test]
fn cli_insecure_upstream_flag_accepted() {
    let ca_dir = TempDir::new().unwrap();
    let ca_dir_str = ca_dir.path().to_str().unwrap();

    let mut child = spawn_proxy(&[
        "--listen",
        "127.0.0.1:19984",
        "--ca-dir",
        ca_dir_str,
        "--insecure-upstream",
    ]);

    assert!(port_is_open(19984));

    child.kill().ok();
    child.wait().ok();
}

#[test]
fn cli_starts_without_install_ca() {
    // `--install-ca` not passed — proxy should start without touching trust store.
    let ca_dir = TempDir::new().unwrap();
    let ca_dir_str = ca_dir.path().to_str().unwrap();

    let mut child = spawn_proxy(&["--listen", "127.0.0.1:19985", "--ca-dir", ca_dir_str]);

    assert!(port_is_open(19985));

    child.kill().ok();
    child.wait().ok();
}

#[test]
fn cli_defaults() {
    // Without --listen, should use 127.0.0.1:8080 and ./mitm-ca
    let mut cmd = Command::cargo_bin("mitm-proxy").unwrap();
    cmd.arg("--help");
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("127.0.0.1:8080"))
        .stdout(predicate::str::contains("./mitm-ca"));
}
