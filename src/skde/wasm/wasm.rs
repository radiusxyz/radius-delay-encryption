use serde_wasm_bindgen::{self, from_value, to_value};
use skde::delay_encryption::{
    decrypt as decryptor, encrypt as encryptor, PublicKey, SecretKey, SkdeParams,
};
use wasm_bindgen::{prelude::*, JsValue};

#[wasm_bindgen]
pub fn encrypt(skde_params: JsValue, message: JsValue, encryption_key: JsValue) -> JsValue {
    let skde_params: SkdeParams = from_value(skde_params).unwrap();
    let message: String = message.as_string().unwrap();
    let encryption_key: PublicKey = from_value(encryption_key).unwrap();

    match encryptor(&skde_params, &message, &encryption_key) {
        Ok(ciphertext) => to_value(&ciphertext.to_string()).unwrap_or(JsValue::null()),
        Err(_) => JsValue::null(),
    }
}

#[wasm_bindgen]
pub fn decrypt(skde_params: JsValue, ciphertext: &str, decryption_key: JsValue) -> JsValue {
    let skde_params: SkdeParams = from_value(skde_params).unwrap();
    let decryption_key: SecretKey = from_value(decryption_key).unwrap();

    match decryptor(&skde_params, ciphertext, &decryption_key) {
        Ok(message) => to_value(&message).unwrap_or(JsValue::null()),
        Err(_) => JsValue::null(),
    }
}
