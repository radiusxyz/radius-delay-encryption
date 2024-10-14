use std::str::FromStr;

use num_bigint::BigUint;
use serde::{Deserialize, Serialize};
use serde_wasm_bindgen::{from_value, to_value};
use skde::delay_encryption::{
    decrypt as decryptor, encrypt as encryptor, PublicKey, SecretKey, SkdeParams,
};
use wasm_bindgen::{prelude::*, JsValue};

#[derive(Deserialize)]
struct SkdeParamsJson {
    n: String,
    g: String,
    t: u32,
    h: String,
    max_sequencer_number: String,
}

#[derive(Deserialize)]
struct PublicKeyJson {
    pk: String,
}

#[derive(Deserialize)]
struct SecretKeyJson {
    sk: String,
}

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = console)]
    fn log(s: &str);
}

#[wasm_bindgen]
pub fn encrypt(skde_params: JsValue, message: JsValue, encryption_key: JsValue) -> JsValue {
    let message: String = match message.as_string() {
        Some(msg) => msg,
        None => {
            log("Failed to convert message to string.");
            return JsValue::from_str("Error: Failed to convert message to string.");
        }
    };

    log(&format!("message: {:?}", message));

    let skde_params_json: SkdeParamsJson = match from_value(skde_params) {
        Ok(params) => params,
        Err(e) => {
            log(&format!("Failed to deserialize skde_params: {:?}", e));
            return JsValue::from_str("Error: Failed to deserialize skde_params.");
        }
    };

    let skde_params = SkdeParams {
        n: BigUint::from_str(&skde_params_json.n).unwrap(),
        g: BigUint::from_str(&skde_params_json.g).unwrap(),
        t: skde_params_json.t,
        h: BigUint::from_str(&skde_params_json.h).unwrap(),
        max_sequencer_number: BigUint::from_str(&skde_params_json.max_sequencer_number).unwrap(),
    };

    log(&format!("skde_params: {:?}", skde_params));

    let encryption_key_json: PublicKeyJson = match from_value(encryption_key) {
        Ok(key) => key,
        Err(e) => {
            log(&format!("Failed to deserialize encryption_key: {:?}", e));
            return JsValue::from_str("Error: Failed to deserialize encryption_key.");
        }
    };

    let encryption_key = PublicKey {
        pk: BigUint::from_str(&encryption_key_json.pk).unwrap(),
    };

    log(&format!("encryption_key: {:?}", encryption_key));

    match encryptor(&skde_params, &message, &encryption_key) {
        Ok(ciphertext) => to_value(&ciphertext.to_string()).unwrap_or(JsValue::null()),
        Err(_) => {
            log("Encryption failed.");
            JsValue::from_str("Error: Encryption failed.")
        }
    }
}

#[wasm_bindgen]
pub fn decrypt(skde_params: JsValue, ciphertext: JsValue, decryption_key: JsValue) -> JsValue {
    let skde_params_json: SkdeParamsJson = match from_value(skde_params) {
        Ok(params) => params,
        Err(e) => {
            log(&format!("Failed to deserialize skde_params: {:?}", e));
            return JsValue::from_str("Error: Failed to deserialize skde_params.");
        }
    };

    let skde_params = SkdeParams {
        n: BigUint::from_str(&skde_params_json.n).unwrap(),
        g: BigUint::from_str(&skde_params_json.g).unwrap(),
        t: skde_params_json.t,
        h: BigUint::from_str(&skde_params_json.h).unwrap(),
        max_sequencer_number: BigUint::from_str(&skde_params_json.max_sequencer_number).unwrap(),
    };

    log(&format!("skde_params: {:?}", skde_params));

    let ciphertext: String = match ciphertext.as_string() {
        Some(ciphertext) => ciphertext,
        None => {
            log("Failed to convert ciphertext to string.");
            return JsValue::from_str("Error: Failed to convert ciphertext to string.");
        }
    };

    log(&format!("ciphertext: {:?}", ciphertext));

    let decryption_key_json: SecretKeyJson = match from_value(decryption_key) {
        Ok(key) => key,
        Err(e) => {
            log(&format!("Failed to deserialize decryption_key: {:?}", e));
            return JsValue::from_str("Error: Failed to deserialize decryption_key.");
        }
    };

    let decryption_key = SecretKey {
        sk: BigUint::from_str(&decryption_key_json.sk).unwrap(),
    };

    log(&format!("decryption_key: {:?}", decryption_key));

    match decryptor(&skde_params, &ciphertext, &decryption_key) {
        Ok(decrypted_message) => {
            to_value(&decrypted_message.to_string()).unwrap_or(JsValue::null())
        }
        Err(_) => JsValue::null(),
    }
}
