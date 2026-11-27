import init, { inspectCapture, maxCaptureBytes } from './testls_wasm.js';

self.onmessage = async ({data: file}) => {
  try {
    await init();
    if (file.size > maxCaptureBytes()) throw new Error('capture exceeds 64 MiB');
    self.postMessage(inspectCapture(new Uint8Array(await file.arrayBuffer())));
  } catch (error) {
    self.postMessage(`Could not read capture: ${error.message}`);
  }
};
