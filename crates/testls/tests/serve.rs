//! End-to-end shutdown of `testls serve`: one interrupt stops it cleanly,
//! a second one stops it at once while a progress stream holds it open.
#![cfg(unix)]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Child, ChildStderr, Command, Stdio};

/// Starts `testls serve` on a free loopback port and returns the child,
/// its stderr and the listen address.
fn start() -> (Child, BufReader<ChildStderr>, String) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_testls"))
        .args(["serve", "--listen", "127.0.0.1:0", "--allow-private"])
        .stderr(Stdio::piped())
        .spawn()
        .expect("run testls serve");
    let mut stderr = BufReader::new(child.stderr.take().expect("stderr"));
    let mut line = String::new();
    stderr.read_line(&mut line).expect("read listen address");
    let server = line
        .trim()
        .rsplit("http://")
        .next()
        .expect("listen address")
        .to_owned();
    (child, stderr, server)
}

/// Sends SIGINT to `child`.
fn interrupt(child: &Child) {
    let status = Command::new("kill")
        .args(["-INT", &child.id().to_string()])
        .status()
        .expect("run kill");
    assert!(status.success());
}

/// Reads stderr until a line contains `needle`, and returns everything read.
fn read_until(stderr: &mut BufReader<ChildStderr>, needle: &str) -> String {
    let mut seen = String::new();
    while !seen.contains(needle) {
        let mut line = String::new();
        if stderr.read_line(&mut line).expect("read stderr") == 0 {
            break;
        }
        seen.push_str(&line);
    }
    seen
}

/// An idle service stops with exit code 0 on the first interrupt.
#[test]
fn interrupt_stops() {
    let (mut child, mut stderr, _) = start();
    interrupt(&child);
    let status = child.wait().expect("reap testls serve");
    let mut rest = String::new();
    stderr.read_to_string(&mut rest).expect("read stderr");
    assert!(status.success(), "{status}: {rest}");
    assert!(rest.contains("shutting down"), "{rest}");
}

/// While a progress stream keeps the service busy, a second interrupt
/// stops it at once with exit code 130.
#[test]
fn second_interrupt_forces() {
    // Accepts the scan's connections and never answers, so it keeps running.
    let target = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = target.local_addr().expect("address");
    let (mut child, mut stderr, server) = start();

    let body = format!(r#"{{"target":"{addr}"}}"#);
    let mut post = TcpStream::connect(&server).expect("connect");
    write!(
        post,
        "POST /scans HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
    .expect("send scan");
    let mut reply = String::new();
    post.read_to_string(&mut reply).expect("read reply");
    assert!(reply.starts_with("HTTP/1.1 202"), "{reply}");

    let mut events = TcpStream::connect(&server).expect("connect");
    write!(
        events,
        "GET /scans/1/events HTTP/1.1\r\nHost: localhost\r\n\r\n"
    )
    .expect("open progress stream");
    let mut head = [0u8; 12];
    events.read_exact(&mut head).expect("stream reply");
    assert_eq!(&head, b"HTTP/1.1 200");

    interrupt(&child);
    let seen = read_until(&mut stderr, "shutting down");
    assert!(seen.contains("shutting down"), "{seen}");
    interrupt(&child);
    let status = child.wait().expect("reap testls serve");
    assert_eq!(status.code(), Some(130), "{status}");
    drop(target);
}
