#!/bin/sh
# Build the browser module and its local-file viewer, from the workspace root.
set -eu
target=${CARGO_TARGET_DIR:-target}
out=$target/pcap-web
# Use the viewer's output root even when Cargo has a different build.target-dir.
# Request a cdylib only for Wasm; native static targets do not support one.
cargo rustc --target-dir "$target" --locked --release -p testls-wasm --lib --target wasm32-unknown-unknown --crate-type cdylib
wasm-bindgen --target web --out-dir "$out" "$target/wasm32-unknown-unknown/release/testls_wasm.wasm"
cp crates/testls-wasm/web/* "$out/"
