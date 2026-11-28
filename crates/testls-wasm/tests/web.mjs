// Exercise the generated web bindings with real Wasm; no network or npm packages.
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

const dir = resolve(process.env.CARGO_TARGET_DIR || 'target', 'pcap-web');
const { default: init, inspectCapture, maxCaptureBytes } =
  await import(pathToFileURL(resolve(dir, 'testls_wasm.js')));
await init({ module_or_path: await readFile(resolve(dir, 'testls_wasm_bg.wasm')) });

const header = Uint8Array.of(0xd4, 0xc3, 0xb2, 0xa1, 2, 0, 4, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 255, 255, 0, 0, 101, 0, 0, 0);
assert.equal(inspectCapture(header), 'Packets read: 0; visible TLS hellos: 0\n');
assert.equal(maxCaptureBytes(), 64 * 1024 * 1024);
assert.throws(() => inspectCapture(new Uint8Array(maxCaptureBytes() + 1)), /exceeds 64 MiB/);

// Raw IPv4 + TCP SYN-ACK carrying a TLS 1.2 ServerHello, cipher 0x002f.
const record = new Uint8Array(16 + 87);
record[8] = record[12] = 87;
const ip = record.subarray(16);
ip[0] = 0x45; ip[3] = 87; ip[9] = 6;
ip.set([192, 0, 2, 1, 192, 0, 2, 2, 1, 187, 4, 0], 12);
ip[32] = 0x50; ip[33] = 18;
ip.set([22, 3, 3, 0, 42, 2, 0, 0, 38, 3, 3], 40);
ip.set([0, 0, 47, 0], 83);
const capture = new Uint8Array(header.length + record.length * 2049);
capture.set(header);
for (let i = 0; i < 2049; i++) {
  // Each packet represents a new flow, with a distinct server port.
  new DataView(record.buffer).setUint16(16 + 20, 443 + i);
  capture.set(record, header.length + i * record.length);
}
const text = inspectCapture(capture);
assert.match(text, /192\.0\.2\.1:443 -> 192\.0\.2\.2:1024  ServerHello selected=TLSv1\.2 cipher=0x002f/);
assert.equal(text.match(/ServerHello/g).length, 2048);
assert.match(text, /Additional hellos omitted: 1\nPackets read: 2049; visible TLS hellos: 2049\n$/);
assert.throws(() => inspectCapture(capture.subarray(0, -1)), /pcap packet data/);
