//! Offline CLI contract: distinguish observed, empty and malformed captures.

use std::{path::PathBuf, process::Command};

/// Run against synthetic capture bytes using a per-test regular file.
fn invoke(bytes: &[u8]) -> (Option<i32>, String, String) {
    let path = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("capture-{}.pcap", std::process::id()));
    std::fs::write(&path, bytes).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_testls"))
        .arg("pcap")
        .arg(&path)
        .output()
        .unwrap();
    std::fs::remove_file(path).unwrap();
    (
        output.status.code(),
        String::from_utf8(output.stdout).unwrap(),
        String::from_utf8(output.stderr).unwrap(),
    )
}

/// A raw IPv4 SYN-ACK carrying a simple TLS 1.2 server hello succeeds;
/// a truncated trailing packet header instead requires exit code 2.
#[test]
fn offline_import() {
    let mut file = vec![
        0xd4, 0xc3, 0xb2, 0xa1, 2, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0, 0, 101, 0, 0, 0,
    ];
    assert_eq!(
        invoke(&file),
        (
            Some(0),
            "Packets read: 0; visible TLS hellos: 0\n".into(),
            String::new()
        )
    );
    let mut ip = vec![0; 40];
    ip[0] = 0x45;
    ip[3] = 87;
    ip[9] = 6;
    ip[12..20].copy_from_slice(&[192, 0, 2, 1, 192, 0, 2, 2]);
    ip[20..24].copy_from_slice(&[1, 187, 4, 0]);
    ip[32] = 0x50;
    ip[33] = 18;
    ip.extend([22, 3, 3, 0, 42, 2, 0, 0, 38, 3, 3]);
    ip.extend([0; 32]);
    ip.extend([0, 0, 47, 0]);
    file.extend([0; 8]);
    file.extend(87u32.to_le_bytes());
    file.extend(87u32.to_le_bytes());
    file.extend(ip);
    let (code, out, err) = invoke(&file);
    assert_eq!(code, Some(0), "{err}");
    assert!(
        out.contains("192.0.2.1:443 -> 192.0.2.2:1024  ServerHello selected=TLSv1.2 cipher=0x002f"),
        "{out}"
    );
    assert!(out.contains("Packets read: 1; visible TLS hellos: 1"));
    file.push(0);
    let (code, _, err) = invoke(&file);
    assert_eq!(code, Some(2));
    assert!(err.contains("pcap packet header"), "{err}");
}
