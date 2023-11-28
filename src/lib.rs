/*

Client message structure (RSA encoded, maximum request data length ~ 430 bytes for RSA 4096):
|AES key - 32 bytes|AES gcm nonce - 12 bytes|Request data|sha256 of request data - 32 bytes|

Request data for S3:
|operation id (GET/PUT) - 1 byte|file name length - 1 byte|file name|s3 password|

Server message structure:
|Response + sha256 of response data encrypted with AES-GCM|

Response data for S3:
|S3 presigned URL|

*/

pub mod client;
pub mod server;
pub mod network;

use std::fs;
use std::io::{Error, ErrorKind};
use pkcs8::DecodePrivateKey;
use rsa::RsaPrivateKey;
use sha2::{Sha256, Digest};

pub const MAX_PACKET_LENGTH: usize = 65535;

pub fn check_hash(decoded: &[u8]) -> Result<&[u8], Error> {
    if decoded.len() < 32 {
        return Err(Error::new(ErrorKind::InvalidData, "check_hash: too short data"));
    }
    let mut hasher = Sha256::new();
    let l = decoded.len() - 32;
    let d = &decoded[0..l];
    hasher.update(d);
    let hash = hasher.finalize();
    let hash_bytes = hash.as_slice();
    if *hash_bytes != decoded[l..] {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "data hash does not match",
        ));
    }
    Ok(d)
}

pub fn add_hash(data: &mut Vec<u8>) {
    let mut hasher = Sha256::new();
    hasher.update(&data);
    let hash = hasher.finalize();
    data.extend_from_slice(hash.as_slice());
}

pub fn build_private_key(private_key: &str) -> Result<RsaPrivateKey, Error> {
    RsaPrivateKey::from_pkcs8_pem(private_key)
        .map_err(|e| Error::new(ErrorKind::Other, e.to_string()))
}

pub fn load_key_file(file_name: &str) -> Result<String, Error> {
    fs::read_to_string(file_name)
        .map_err(|e|Error::new(ErrorKind::InvalidData, e.to_string()))
}

#[cfg(test)]
mod tests {
    use std::io::Error;
    use rand::Rng;
    use rsa::RsaPrivateKey;
    use crate::client::{client_decrypt, client_encrypt};
    use crate::{build_private_key, load_key_file};
    use crate::network::QHandler;
    use crate::server::packet_handler;

    struct TestHandler {

    }

    impl QHandler for TestHandler {
        fn handle(&self, data: &[u8]) -> Result<Option<Vec<u8>>, Error> {
            Ok(Some(data.to_vec()))
        }
    }

    #[test]
    fn test_encryption() -> Result<(), Error> {
        let (public_key, private_key) = load_test_keys()?;
        let mut rng = rand::thread_rng();
        let pk = public_key.as_str();

        let src_data: Vec<u8> = (0..100).map(|_| rng.gen()).collect();
        test_encryption_data(pk, &private_key, src_data)?;

        let src_data: Vec<u8> = (0..200).map(|_| rng.gen()).collect();
        test_encryption_data(pk, &private_key, src_data)?;

        let src_data: Vec<u8> = (0..300).map(|_| rng.gen()).collect();
        test_encryption_data(pk, &private_key, src_data)?;

        let src_data: Vec<u8> = (0..420).map(|_| rng.gen()).collect();
        test_encryption_data(pk, &private_key, src_data)
    }

    fn test_encryption_data(public_key: &str, private_key: &RsaPrivateKey, src_data: Vec<u8>)
        -> Result<(), Error> {
        let (encrypted, aes_key, nonce) =
            client_encrypt(public_key, src_data.clone())?;
        let handler: Box<dyn QHandler> = Box::new(TestHandler{});
        let response = packet_handler(&private_key, encrypted.as_slice(), &handler)?;
        assert!(response.is_some());
        let decrypted = client_decrypt(response.unwrap().as_slice(), aes_key, nonce)?;
        assert_eq!(decrypted, src_data);
        Ok(())
    }

    fn load_test_keys() -> Result<(String, RsaPrivateKey), Error> {
        let public_key = load_key_file("test_data/test_rsa.pem.pub")?;
        let private_key =
            build_private_key(load_key_file("test_data/test_rsa.pem")?.as_str())?;
        Ok((public_key, private_key))
    }
}
