// skde.js

import init, { encrypt, decrypt } from "./pkg/skde-wasm.js";

let initialized = false;
async function ensureInitialized() {
  if (!initialized) {
    try {
      const contents = await snap.request({
        method: "snap_getFile",
        params: {
          path: "./build/pvde_bg.wasm",
          encoding: "base64",
        },
      });

      const buffer = base64ToArrayBuffer(contents);
      const wasmModule = await init(buffer);

      await init(wasmModule);

      initialized = true;
    } catch (error) {
      console.log("stompesi error", error);
    }
  }
}

async function encryptMessage(skdeParams, message, encryptionKey) {
  await ensureInitialized();
  return encrypt(skdeParams, message, encryptionKey);
}

async function decryptCipher(skdeParams, cipherText, secretKey) {
  await ensureInitialized();
  return decrypt(skdeParams, cipherText, secretKey);
}

export default { encryptMessage, decryptCipher };
