use std::io::{Error, ErrorKind};
use std::net::{ToSocketAddrs, UdpSocket};
use aes_gcm::{AeadCore, Aes256Gcm, KeyInit};
use aes_gcm::aead::{Aead, Nonce};
use pkcs8::DecodePublicKey;
use rand::RngCore;
use rand::rngs::OsRng;
use rsa::{Pkcs1v15Encrypt, RsaPublicKey};
use crate::{add_hash, check_hash};
use crate::network::qsend_to;

pub fn qsend(
    server_public_key: &str,
    host_name: &String,
    data: Vec<u8>,
    read_timeout: u64,
    retries: usize,
) -> Result<Vec<u8>, Error> {
    let addr = host_name
        .to_socket_addrs()?
        .next()
        .ok_or(Error::new(ErrorKind::Unsupported, "invalid address"))?;
    let (encrypted, aes_key, nonce) =
        client_encrypt(server_public_key, data)?;
    let socket = UdpSocket::bind((addr.ip(), 0))?;
    let response = qsend_to(socket, addr, encrypted, read_timeout, retries)?;
    client_decrypt(response.as_slice(), aes_key, nonce)
}

pub fn client_decrypt(response: &[u8], aes_key: [u8; 32], nonce: Nonce<Aes256Gcm>)
    -> Result<Vec<u8>, Error> {
    if response.len() < 16 + 32 {
        return Err(Error::new(ErrorKind::InvalidData, "client_decrypt: too short response"));
    }
    let cipher = Aes256Gcm::new(&aes_key.into());
    let decrypted = cipher.decrypt(&nonce, response)
        .map_err(|e| Error::new(ErrorKind::InvalidData, e.to_string()))?;
    let without_hash = check_hash(decrypted.as_slice())?;
    Ok(without_hash.to_vec())
}

pub fn client_encrypt(
    server_public_key: &str,
    request: Vec<u8>,
) -> Result<(Vec<u8>, [u8; 32], Nonce<Aes256Gcm>), Error> {
    let key = RsaPublicKey::from_public_key_pem(server_public_key)
        .map_err(|e| Error::new(ErrorKind::Other, e.to_string()))?;

    // random 32 byte AES key
    let mut aes_key = [0u8; 32];
    OsRng.fill_bytes(&mut aes_key);
    let mut data = aes_key.to_vec();

    // random nonce
    let mut rng = rand::thread_rng();
    let nonce = Aes256Gcm::generate_nonce(&mut rng);
    data.extend_from_slice(nonce.as_slice());

    // adding request
    data.extend_from_slice(&request);

    // adding sha256 hash
    add_hash(&mut data);

    let rsa_encrypted = key.encrypt(&mut rng, Pkcs1v15Encrypt, &data)
        .map_err(|e| Error::new(ErrorKind::Other, e.to_string()))?;

    Ok((rsa_encrypted, aes_key, nonce))
}
