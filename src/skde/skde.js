// skde.js

import init, { encrypt, decrypt } from "./wasm/pkg/skde_wasm.js";

let initialized = false;
async function ensureInitialized() {
  if (!initialized) {
    await init();
    initialized = true;
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
