use serde_wasm_bindgen::{self, from_value};
use wasm_bindgen::{prelude::*, JsValue};

use crate::delay_encryption::{
    decrypt as decryptor, encrypt as encryptor, PublicKey, SecretKey, SkdeParams,
};

#[wasm_bindgen]
pub fn encrypt(
    skde_params: JsValue,
    message: JsValue,
    encryption_key: JsValue,
) -> Result<String, JsValue> {
    let skde_params: SkdeParams = from_value(skde_params).unwrap();
    let message: String = message.as_string().unwrap();
    let encryption_key: PublicKey = from_value(encryption_key).unwrap();

    match encryptor(&skde_params, &message, &encryption_key) {
        Ok(ciphertext) => {
            // Convert the ciphertext to JsValue and then to a String
            let ciphertext_str = ciphertext.to_string();
            Ok(ciphertext_str)
        }
        Err(e) => {
            // Handle the error and convert it to JsValue
            Err(JsValue::from_str(&format!("Encryption error: {}", e)))
        }
    }
}

#[wasm_bindgen]
pub fn decrypt(
    skde_params: JsValue,
    ciphertext: &str,
    decryption_key: JsValue,
) -> Result<String, JsValue> {
    let skde_params: SkdeParams = from_value(skde_params).unwrap();
    let decryption_key: SecretKey = from_value(decryption_key).unwrap();

    match decryptor(&skde_params, ciphertext, &decryption_key) {
        Ok(message) => {
            // Convert the decrypted message to a string and return it
            Ok(message)
        }
        Err(e) => {
            // Handle the error and convert it to JsValue
            Err(JsValue::from_str(&format!("Decryption error: {}", e)))
        }
    }
}
