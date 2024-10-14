use std::str::FromStr;

use num_bigint::BigUint;
use serde_wasm_bindgen::{from_value, to_value};
use skde::delay_encryption::{
    decrypt as decryptor, encrypt as encryptor, PublicKey, SecretKey, SkdeParams,
};
use wasm_bindgen::{prelude::*, JsValue};

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
            return JsValue::from_str(
                "Error: Failed to convert message to
    string.",
            );
        }
    };

    log(&format!("message: {:?}", message));

    let skde_params: SkdeParams = match from_value(skde_params) {
        Ok(params) => params,
        Err(e) => {
            log(&format!("Failed to deserialize skde_params: {:?}", e));
            return JsValue::from_str(
                "Error: Failed to deserialize
    skde_params.",
            );
        }
    };

    log(&format!("skde_params: {:?}", skde_params));

    let encryption_key: PublicKey = match from_value(encryption_key) {
        Ok(key) => key,
        Err(e) => {
            log(&format!("Failed to deserialize encryption_key: {:?}", e));
            return JsValue::from_str(
                "Error: Failed to deserialize
    encryption_key.",
            );
        }
    };

    log(&format!("encryption_key: {:?}", encryption_key));

    let skde_params = SkdeParams {
        n: BigUint::from_str("109108784166676529682340577929498188950239585527883687884827626040722072371127456712391033422811328348170518576414206624244823392702116014678887602655605057984874271545556188865755301275371611259397284800785551682318694176857633188036311000733221068448165870969366710007572931433736793827320953175136545355129").unwrap(),
        g: BigUint::from(4),
        t: 4,
        h: BigUint::from_str("4294967296").unwrap(),
        max_sequencer_number: BigUint::from_str("2").unwrap(),
    };

    let message =
    "0xf869018203e882520894f17f52151ebef6c7334fad080c5704d77216b732881bc16d674ec80000801ba02da1c48b670996dcb1f447ef9ef00b33033c48a4fe"
    ;

    let encryption_key = PublicKey {
        pk: BigUint::from_str("27897411317866240410600830526788165981341969904039758194675272671868652866892274441298243014317800177611419642993059565060538386730472765976439751299066279239018615809165217144853299923809516494049479159549907327351509242281465077907977695359158281231729142725042643997952251325328973964444619144348848423785").unwrap(),
    };

    // Perform encryption
    match encryptor(&skde_params, &message, &encryption_key) {
        Ok(ciphertext) => to_value(&ciphertext.to_string()).unwrap_or(JsValue::null()),
        Err(_) => {
            log("Encryption failed.");
            JsValue::from_str("Error: Encryption failed.")
        }
    }
}

#[wasm_bindgen]
pub fn decrypt() -> JsValue {
    // Declare local variables for decryption
    let skde_params = SkdeParams {
        n: BigUint::from_str("109108784166676529682340577929498188950239585527883687884827626040722072371127456712391033422811328348170518576414206624244823392702116014678887602655605057984874271545556188865755301275371611259397284800785551682318694176857633188036311000733221068448165870969366710007572931433736793827320953175136545355129").unwrap(),
        g: BigUint::from(4u32),
        t: 4,
        h: BigUint::from_str("4294967296").unwrap(),
        max_sequencer_number: BigUint::from_str("2").unwrap(),
    };

    let ciphertext = "0x010000000000000020000000000000009f334447e3afdda48a1244e2680e14b9b2cacfeb07b81d2a46fffd9aef265477f68458d843b980d367dfa40b65ed770c5585562db0f1fd4e402671720003b8106fba48561863bd16f21c2968d1225a5ab846d787751ef5dcb0fe795cb28b237671558a7be7c7f8b79f6a58c5039fd950f8fdee6072d78a5a242dcccc380ba72220000000000000004ebb09d8e18896954d85178299497df7a75b2455719a9d4544f0fce237d6d6695c44c5a1f9b5155e134710777ee76f2758db461112b4ef4c5289906dbf1d52ecd1dad43c86e0b99ff395b5557580da7b5c1822837315a26fc560deb074e354d3065fd1e968c594e23297408c983a2cf98160e09ed8dc65a3bd50e769ffb6740f"; // Example encrypted message

    let decryption_key = SecretKey {
        sk: BigUint::from_str("38833048300325516141445839739644018404110477961707775037115236576780421892476578378034582536195146817009345764092161668346878367282186498795101059094681709712929905024483143171658282800283336368593335787557451643648363431385562973837024404466434120134771798848006526362428133799287842185760112952945802615179").unwrap(),
    };

    // Perform decryption and handle the result
    match decryptor(&skde_params, ciphertext, &decryption_key) {
        Ok(_) => to_value("success").unwrap_or(JsValue::null()), // Return "success" as JsValue
        Err(_) => JsValue::null(),                               // Return null in case of an error
    }
}
