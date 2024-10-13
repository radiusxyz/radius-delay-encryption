use serde_wasm_bindgen::{self, from_value};
use skde::delay_encryption::{
    decrypt as decryptor, encrypt as encryptor, PublicKey, SecretKey, SkdeParams,
};
use wasm_bindgen::{prelude::*, JsValue};

#[wasm_bindgen]
pub fn encrypt(
    skde_params: JsValue,
    message: JsValue,
    encryption_key: JsValue,
) -> Result<String, JsValue> {
    // Deserialize the input values from JsValue to Rust types
    let skde_params: SkdeParams = from_value(skde_params).unwrap();
    let message: String = message.as_string().unwrap();
    let encryption_key: PublicKey = from_value(encryption_key).unwrap();

    // Perform encryption and handle the result
    match encryptor(&skde_params, &message, &encryption_key) {
        Ok(ciphertext) => Ok(ciphertext.to_string()), // Return ciphertext as a string
        Err(e) => Err(JsValue::from_str(&format!("Encryption error: {}", e))), // Handle error case
    }
}

#[wasm_bindgen]
pub fn decrypt(
    skde_params: JsValue,
    ciphertext: &str,
    decryption_key: JsValue,
) -> Result<String, JsValue> {
    // Deserialize the input values from JsValue to Rust types
    let skde_params: SkdeParams = from_value(skde_params).unwrap();
    let decryption_key: SecretKey = from_value(decryption_key).unwrap();

    // Perform decryption and handle the result
    match decryptor(&skde_params, ciphertext, &decryption_key) {
        Ok(message) => Ok(message), // Return the decrypted message
        Err(e) => Err(JsValue::from_str(&format!("Decryption error: {}", e))), // Handle error case
    }
}
