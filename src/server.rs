use std::io::{Error, ErrorKind};
use aes_gcm::{Aes256Gcm, KeyInit};
use aes_gcm::aead::Aead;
use aes_gcm::aead::consts::U12;
use rsa::{Pkcs1v15Encrypt, RsaPrivateKey};
use sha2::digest::generic_array::GenericArray;
use crate::{add_hash, check_hash};

fn server_encrypt(mut data: Vec<u8>, cipher: Aes256Gcm, nonce: &GenericArray<u8, U12>) -> Result<Vec<u8>, Error> {
    add_hash(&mut data);
    cipher.encrypt(nonce, data.as_slice())
        .map_err(|e| Error::new(ErrorKind::InvalidData, e.to_string()))
}

pub fn packet_handler(
    key: &RsaPrivateKey,
    data: &[u8],
    handler: fn(data: &[u8]) -> Result<Option<Vec<u8>>, Error>
) -> Result<Option<Vec<u8>>, Error> {
    match key.decrypt(Pkcs1v15Encrypt, data) {
        Ok(request) => {
            if request.len() <= 64+12 {
                return Err(Error::new(ErrorKind::InvalidData, "RSA decrypted data has invalid length"));
            }
            let r = check_hash(request.as_slice())?;
            let mut aes_key = [0u8; 32];
            aes_key.copy_from_slice(&r[0..32]);
            let nonce: &GenericArray<u8, U12> = aes_gcm::Nonce::from_slice(&r[32..44]);
            run_handler(&r[44..], aes_key, handler, nonce)
        },
        Err(e) => {
            println!("RSA decryption error {}", e.to_string());
            Ok(None)
        }
    }
}

fn run_handler(
    data: &[u8],
    aes_key: [u8; 32],
    handler: fn(data: &[u8]) -> Result<Option<Vec<u8>>, Error>,
    nonce: &GenericArray<u8, U12>
) -> Result<Option<Vec<u8>>, Error> {
    let cipher = Aes256Gcm::new(&aes_key.into());
    match handler(data) {
        Ok(r) => {
            if let Some(response) = r {
                match server_encrypt(response, cipher, nonce) {
                    Ok(encoded) => Ok(Some(encoded)),
                    Err(_e) => {
                        println!("response encryption error");
                        Ok(None)
                    }
                }
            } else {
                Ok(None)
            }
        }
        Err(e) => {
            println!("handler returned error {}", e);
            Err(e)
        }
    }
}
