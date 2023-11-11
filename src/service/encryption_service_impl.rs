use std::io::{Cursor, Read};
use byteorder::{ReadBytesExt, WriteBytesExt};
use crate::crypto;
use crate::domain::models::{DecryptRequest, EncodingScheme, EncryptRequest, PassConfig, PassResult};
use crate::service::EncryptionService;

#[derive(Clone)]
pub(crate) struct EncryptionServiceImpl {
    config: PassConfig,
}

impl EncryptionServiceImpl {
    pub fn new(config: &PassConfig) -> Self {
        Self {
            config: config.clone(),
        }
    }
    fn encode_salt_nonce(salt: &str, nonce: &str, data: Vec<u8>) -> PassResult<Vec<u8>> {
        let salt_bytes = salt.as_bytes();
        let nonce_bytes = nonce.as_bytes();

        let mut encoded = Vec::new();
        let _ = encoded.write_u16::<byteorder::LittleEndian>(salt_bytes.len() as u16)?;
        encoded.extend_from_slice(salt_bytes);

        let _ = encoded.write_u16::<byteorder::LittleEndian>(nonce_bytes.len() as u16)?;
        encoded.extend_from_slice(nonce_bytes);
        encoded.extend_from_slice(&data);
        Ok(encoded)
    }

    fn decode_salt_nonce(encoded: Vec<u8>) -> PassResult<(String, String, Vec<u8>)> {
        let mut cursor = Cursor::new(encoded);

        let salt_len = cursor.read_u16::<byteorder::LittleEndian>()? as usize;
        let mut salt_bytes = vec![0u8; salt_len];
        cursor.read_exact(&mut salt_bytes)?;
        let salt = String::from_utf8(salt_bytes)?;

        let nonce_len = cursor.read_u16::<byteorder::LittleEndian>()? as usize;
        let mut nonce_bytes = vec![0u8; nonce_len];
        cursor.read_exact(&mut nonce_bytes)?;
        let nonce = String::from_utf8(nonce_bytes)?;

        let mut payload = Vec::new();
        cursor.read_to_end(&mut payload)?;

        Ok((salt, nonce, payload))
    }
}

impl EncryptionService for EncryptionServiceImpl {
    fn generate_private_public_keys(&self,
                                    secret: Option<String>) -> PassResult<(String, String)> {
        if let Some(secret) = secret {
            crypto::generate_private_public_keys_from_secret(&secret)
        } else {
            Ok(crypto::generate_private_public_keys())
        }
    }

    fn asymmetric_encrypt(&self,
                          pk: &str,
                          data: Vec<u8>,
                          encoding: EncodingScheme) -> PassResult<Vec<u8>> {
        // Encrypt data using hex public key
        let bytes = crypto::ec_encrypt_hex_bytes(pk, &data)?;
        // Encode payload to bytes
        if encoding == EncodingScheme::None {
            Ok(bytes.clone())
        } else {
            Ok(encoding.encode(bytes)?.as_bytes().to_vec())
        }
    }

    fn asymmetric_decrypt(&self,
                          sk: &str,
                          data: Vec<u8>,
                          encoding: EncodingScheme) -> PassResult<Vec<u8>> {
        // Decode payload
        let data = if encoding == EncodingScheme::None {
            data
        } else {
            encoding.decode(&String::from_utf8(data)?)?
        };
        // Decrypt payload using hex secret key
        let bytes = crypto::ec_decrypt_hex_bytes(sk, &data)?;
        Ok(bytes)
    }

    fn symmetric_encrypt(&self,
                         salt: &str,
                         pepper: &str,
                         secret: &str,
                         data: Vec<u8>,
                         encoding: EncodingScheme) -> PassResult<Vec<u8>> {
        let salt = if salt.len() < 8 {
            hex::encode(crypto::generate_nonce())
        } else {
            salt.to_string()
        };
        let enc_val_resp = crypto::encrypt(EncryptRequest::new(
            &salt,
            pepper,
            secret,
            self.config.hash_algorithm(),
            self.config.crypto_algorithm(),
            data,
            encoding.clone(),
        ))?;
        let payload = if encoding == EncodingScheme::None {
            enc_val_resp.cipher_payload
        } else {
            enc_val_resp.encoded_payload()?.as_bytes().to_vec()
        };
        Self::encode_salt_nonce(&salt, &enc_val_resp.nonce, payload)
    }

    fn symmetric_decrypt(&self,
                         pepper: &str,
                         secret: &str,
                         nonce_data: Vec<u8>,
                         encoding: EncodingScheme) -> PassResult<Vec<u8>> {
        let (salt, nonce, data) = Self::decode_salt_nonce(nonce_data)?;
        let payload = if encoding == EncodingScheme::None {
            data
        } else {
            let str = String::from_utf8(data)?;
            encoding.decode(&str)?
        };
        let dec_res = crypto::decrypt(DecryptRequest::new(
            &salt,
            pepper,
            secret,
            self.config.hash_algorithm(),
            self.config.crypto_algorithm(),
            &nonce,
            payload,
            encoding,
        ))?;
        Ok(dec_res.payload)
    }
}

#[cfg(test)]
mod tests {
    use crate::domain::models::{EncodingScheme, PassConfig};
    use crate::service::factory::create_encryption_service;

    #[tokio::test]
    async fn test_should_encrypt_decrypt_asymmetric_raw() {
        let config = PassConfig::new();
        let encryption_svc = create_encryption_service(&config).await.unwrap();
        let (sk, pk) = encryption_svc.generate_private_public_keys(None).unwrap();
        let cipher_payload = encryption_svc.asymmetric_encrypt(
            &pk,
            "payload1".as_bytes().to_vec(),
            EncodingScheme::None,
        ).unwrap();
        let decrypted = encryption_svc.asymmetric_decrypt(
            &sk,
            cipher_payload,
            EncodingScheme::None,
        ).unwrap();
        assert_eq!("payload1".as_bytes().to_vec(), decrypted);
    }

    #[tokio::test]
    async fn test_should_encrypt_decrypt_asymmetric_base64() {
        let config = PassConfig::new();
        let encryption_svc = create_encryption_service(&config).await.unwrap();
        let (sk, pk) = encryption_svc.generate_private_public_keys(None).unwrap();
        let cipher_payload = encryption_svc.asymmetric_encrypt(
            &pk,
            "payload1".as_bytes().to_vec(),
            EncodingScheme::Base64,
        ).unwrap();
        let decrypted = encryption_svc.asymmetric_decrypt(
            &sk,
            cipher_payload,
            EncodingScheme::Base64,
        ).unwrap();
        assert_eq!("payload1".as_bytes().to_vec(), decrypted);
    }

    #[tokio::test]
    async fn test_should_encrypt_decrypt_symmetric_raw() {
        let mut config = PassConfig::new();
        config.crypto_algorithm = "ChaCha20Poly1305".into();
        let encryption_svc = create_encryption_service(&config).await.unwrap();
        let cipher_payload= encryption_svc.symmetric_encrypt(
            "",
            "",
            "master",
            "payload1".as_bytes().to_vec(),
            EncodingScheme::None).unwrap();
        let decrypted = encryption_svc.symmetric_decrypt(
            "",
            "master",
            cipher_payload,
            EncodingScheme::None,
        ).unwrap();
        assert_eq!("payload1".as_bytes().to_vec(), decrypted);
    }

    #[tokio::test]
    async fn test_should_encrypt_decrypt_symmetric_base64() {
        let config = PassConfig::new();
        let encryption_svc = create_encryption_service(&config).await.unwrap();
        let cipher_payload = encryption_svc.symmetric_encrypt(
            "",
            "",
            "master",
            "payload1".as_bytes().to_vec(),
            EncodingScheme::Base64).unwrap();
        let decrypted = encryption_svc.symmetric_decrypt(
            "",
            "master",
            cipher_payload,
            EncodingScheme::Base64,
        ).unwrap();
        assert_eq!("payload1".as_bytes().to_vec(), decrypted);
    }
}
