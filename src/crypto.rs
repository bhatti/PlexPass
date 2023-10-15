extern crate argon2;
extern crate ecies;
extern crate hex;
extern crate ring;
extern crate security_framework;

use std::num::NonZeroU32;

use aes_gcm::aead::generic_array::GenericArray as AesGenericArray;
use aes_gcm::aead::{Aead, Payload as AesPayload};
use aes_gcm::Aes256Gcm;
use aes_gcm::KeyInit;
use argon2::password_hash::errors;
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::generic_array::GenericArray as ChaGenericArray;
use chacha20poly1305::ChaCha20Poly1305;
use ecies::utils::generate_keypair;
use ecies::{PublicKey, SecpError, SecretKey};
use rand::RngCore;
use ring::{digest, pbkdf2};
use sha1::{Digest, Sha1};

use crate::domain::error::PassError;
use crate::domain::models::{
    CryptoAlgorithm, DecryptRequest, DecryptResponse, EncryptRequest, EncryptResponse,
    HashAlgorithm, PassResult, PBKDF2_HMAC_SHA256_ITERATIONS,
};

// Cryptographically secure random number generator

pub const NONCE_LEN: usize = 12;

pub const SECRET_LEN: usize = 32;

/// PUBLIC METHODS FOR HASHING
///
/// Compute Sha1 Hash
pub(crate) fn compute_sha1(input: &str) -> String {
    let hash = Sha1::digest(input.as_bytes());
    hex::encode(hash)
}

/// Compute Sha256 Hash
pub(crate) fn compute_sha256(input: &str) -> String {
    let hash = digest::digest(&digest::SHA256, input.as_bytes());
    hex::encode(hash.as_ref())
}

/// Compute Hash based on HashAlgorithm
pub(crate) fn compute_hash(
    salt: &[u8],
    pepper: &str,
    input: &str,
    alg: HashAlgorithm,
) -> Result<[u8; SECRET_LEN], errors::Error> {
    match alg {
        HashAlgorithm::Pbkdf2HmacSha256 { iterations } => {
            Ok(compute_pbkdf2(input, salt, pepper, iterations))
        }
        HashAlgorithm::ARGON2id {
            memory_mi_b,
            iterations,
            parallelism,
        } => compute_argon2id(input, salt, pepper, memory_mi_b, iterations, parallelism),
    }
}

/// Generate a new random nonce for AES-GCM. (default is 12)
pub(crate) fn generate_nonce() -> [u8; NONCE_LEN] {
    let mut nonce = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce);
    nonce
}

/// Generate a new random secret key for AES-GCM
pub(crate) fn generate_secret_key() -> [u8; SECRET_LEN] {
    let mut key = [0u8; SECRET_LEN];
    rand::thread_rng().fill_bytes(&mut key);
    key
}

/// Generate a public and private keypair based on Elliptic Curve
pub(crate) fn generate_private_public_keys() -> (String, String) {
    let (sk, pk) = generate_keypair();
    (hex::encode(&sk.serialize()), hex::encode(pk.serialize()))
}

/// Generate a public and private keypair using given secret
pub(crate) fn generate_private_public_keys_from_secret(
    secret: &str,
) -> PassResult<(String, String)> {
    let in_bytes = secret.as_bytes();
    if in_bytes.len() < SECRET_LEN {
        return Err(PassError::validation("secret is too small", None));
    }
    let mut p = [0; SECRET_LEN];
    for i in 0..SECRET_LEN {
        p[i] = in_bytes[i.clone()];
    }
    let sk = SecretKey::parse(&p)?;
    let pk = PublicKey::from_secret_key(&sk);
    Ok((hex::encode(&sk.serialize()), hex::encode(pk.serialize())))
}

/// Encrypt using hex-encoded public key and Elliptic Curve
pub(crate) fn ec_encrypt(pk: &str, msg_str: &str) -> PassResult<String> {
    let msg = msg_str.as_bytes().to_vec();
    let pub_bytes = hex::decode(pk)?;
    Ok(hex::encode(&ecies::encrypt(&pub_bytes, &msg)?))
}

/// Decrypt using hex-encoded secret private key and Elliptic Curve
pub(crate) fn ec_decrypt(sk: &str, msg_str: &str) -> PassResult<String> {
    let msg = hex::decode(msg_str)?;
    let secret_bytes = hex::decode(sk)?;
    Ok(String::from_utf8(ecies::decrypt(&secret_bytes, &msg)?)?)
}

/// ENCRYPTION METHODS
///
/// Encrypt plaintext using crypto-algorithm.
///
/// Returns a tuple of `(nonce, ciphertext)`.
pub(crate) fn encrypt(req: EncryptRequest) -> PassResult<EncryptResponse> {
    let seed_key = compute_hash(
        &req.salt_bytes()?,
        &req.device_pepper,
        &req.master_secret,
        req.hash_algorithm.clone(),
    )?;
    let (nonce, ciphertext) = match req.crypto_algorithm {
        CryptoAlgorithm::Aes256Gcm => {
            aes_encrypt(&seed_key, req.aad.as_bytes(), req.plaintext.as_bytes())?
        }
        CryptoAlgorithm::ChaCha20Poly1305 => cha_encrypt(&seed_key, req.plaintext.as_bytes())?,
    };
    EncryptResponse::new(nonce, ciphertext)
}

/// Decrypt ciphertext using crypto-algorithm.
pub(crate) fn decrypt(req: DecryptRequest) -> PassResult<DecryptResponse> {
    let seed_key = compute_hash(
        &req.salt_bytes()?,
        &req.device_pepper,
        &req.master_secret,
        req.hash_algorithm.clone(),
    )?;
    let ciphertext = match req.crypto_algorithm {
        CryptoAlgorithm::Aes256Gcm => aes_decrypt(
            &seed_key,
            req.aad.as_bytes(),
            &req.nonce_bytes()?,
            &req.ciphertext_bytes()?,
        )?,
        CryptoAlgorithm::ChaCha20Poly1305 => {
            cha_decrypt(&seed_key, &req.nonce_bytes()?, &req.ciphertext_bytes()?)?
        }
    };
    DecryptResponse::new(ciphertext)
}

/// encrypt_file encrypts a file with given key and nonce

/// PRIVATE ENCRYPTION METHODS

/// Encrypt plaintext using AES (Advanced Encryption Standard). AES with a key size of
/// 256 bits (AES-256) is used for symmetric encryption algorithms.
///
/// Returns a tuple of `(nonce, ciphertext)`.
fn aes_encrypt(
    secret_key: &[u8; SECRET_LEN],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), aes_gcm::Error> {
    let key = AesGenericArray::from_slice(secret_key);
    let cipher = Aes256Gcm::new(key);
    let binding = generate_nonce();
    let nonce = AesGenericArray::from_slice(&binding);
    let ciphertext = cipher.encrypt(
        &nonce,
        AesPayload {
            msg: plaintext,
            aad,
        },
    )?;
    Ok((nonce.to_vec(), ciphertext))
}

/// Decrypt ciphertext using AES-GCM.
fn aes_decrypt(
    secret_key: &[u8; SECRET_LEN],
    aad: &[u8],
    nonce: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, aes_gcm::Error> {
    let cipher = Aes256Gcm::new(AesGenericArray::from_slice(secret_key));
    cipher.decrypt(
        AesGenericArray::from_slice(nonce),
        AesPayload {
            msg: ciphertext,
            aad,
        },
    )
}

/// Encrypt plaintext using ChaCha20-Poly1305. ChaCha20 is an alternative to AES,
/// especially in environments where hardware-based AES acceleration is not available.
/// It's used in combination with the Poly1305 MAC, as in the case of the ChaCha20-Poly1305
/// cipher suite in TLS.
///
/// Returns a tuple of `(nonce, ciphertext)`.
fn cha_encrypt(
    secret_key: &[u8; SECRET_LEN],
    plaintext: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), chacha20poly1305::Error> {
    let cipher = ChaCha20Poly1305::new(ChaGenericArray::from_slice(secret_key));
    let binding = generate_nonce();
    let nonce = ChaGenericArray::from_slice(&binding);
    let ciphertext = cipher.encrypt(&nonce, plaintext)?;
    Ok((nonce.to_vec(), ciphertext))
}

/// Decrypt ciphertext using ChaCha20-Poly1305.
fn cha_decrypt(
    secret_key: &[u8; SECRET_LEN],
    nonce: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, chacha20poly1305::Error> {
    let cipher = ChaCha20Poly1305::new(ChaGenericArray::from_slice(secret_key));
    cipher.decrypt(ChaGenericArray::from_slice(nonce), ciphertext)
}

/// PRIVATE HASHING METHODS

/// PBKDF2 with a minimum work factor of 600,000 or more and with an internal hash function
/// of HMAC-SHA-256. pepper and salt to add  additional defense in depth.
// Note: input can be master-password to use as seed for the key.
fn compute_pbkdf2(input: &str, salt: &[u8], pepper: &str, _iterations: u32) -> [u8; 32] {
    type Credential = [u8; digest::SHA256_OUTPUT_LEN];

    let peppered_input = format!("{}{}", input, pepper);
    // Ignoring _iterations as NonZeroU32 requires constant
    const ITER: NonZeroU32 = unsafe { NonZeroU32::new_unchecked(PBKDF2_HMAC_SHA256_ITERATIONS) }; // PBKDF2 iterations
    let mut derived_key = Credential::default();

    pbkdf2::derive(
        pbkdf2::PBKDF2_HMAC_SHA256,
        ITER,
        salt,
        peppered_input.as_bytes(),
        &mut derived_key,
    );
    derived_key
}

/// Argon2 is a password-based key derivation function that is part of the Password Hashing
/// Competition, and it comes in several different versions, including Argon2d. It's
/// designed to be secure against a variety of attacks, and it's highly configurable, allowing
/// you to adjust the time cost, memory cost, and parallelism.
// Note: Argon2 is not directly used for encrypting or decrypting data; rather, it's used to
// derive a cryptographic key from a password, which can then be used to encrypt or
// decrypt data using a symmetric cipher like AES.
// Argon2id with a minimum configuration of 64 MiB of memory, an iteration count of 3,
// and 1 degree of parallelism.
fn compute_argon2id(
    input: &str,
    salt: &[u8],
    pepper: &str,
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
) -> Result<[u8; SECRET_LEN], errors::Error> {
    let peppered_input = format!("{}{}", input, pepper);

    let mut output_key_material = [0u8; SECRET_LEN]; // Can be any desired size
                                                     // Note: default parameters use 19MiB with iteration count of 2 and 1 degree of parallelism.
    let params = Params::new(m_cost, t_cost, p_cost, None)?;
    Argon2::new(Algorithm::default(), Version::default(), params).hash_password_into(
        peppered_input.as_bytes(),
        salt,
        &mut output_key_material,
    )?;
    Ok(output_key_material)
}

// Split the password into chunks by dividing a password into a sequence of trigrams.
fn trigrams(password: &str) -> Vec<&str> {
    let chars: Vec<_> = password.chars().collect();
    let mut trigrams = Vec::new();

    for i in 0..chars.len().saturating_sub(2) {
        trigrams.push(&password[i..i + 3]);
    }

    trigrams
}

// For each chunk, derive a set of features.
// Hashing: For each feature, use a hash function to produce a hash value.
// Combine these hash values into a single hash for the password.
fn tri_hash_password(password: &str) -> u64 {
    let trigrams = trigrams(password);
    let mut hash = 0u64;

    for tri in trigrams {
        for ch in tri.chars() {
            hash += ch as u64; // simplistic hashing: just summing up ASCII values
        }
    }
    hash
}

/// Helper methods to convert crypto
impl From<aes_gcm::Error> for PassError {
    fn from(err: aes_gcm::Error) -> Self {
        PassError::crypto(format!("aes-gcm encryption failed {:?}", err).as_str())
    }
}

impl From<argon2::password_hash::Error> for PassError {
    fn from(err: argon2::password_hash::Error) -> Self {
        PassError::crypto(format!("argon encryption failed {:?}", err).as_str())
    }
}

impl From<security_framework::base::Error> for PassError {
    fn from(err: security_framework::base::Error) -> Self {
        PassError::crypto(format!("keychain failed {:?}", err).as_str())
    }
}

impl From<SecpError> for PassError {
    fn from(err: SecpError) -> Self {
        PassError::crypto(format!("secp encryption failed {:?}", err).as_str())
    }
}

#[cfg(test)]
mod tests {
    use crate::crypto::{
        aes_decrypt, aes_encrypt, cha_decrypt, cha_encrypt, compute_argon2id, compute_hash,
        compute_pbkdf2, compute_sha1, compute_sha256, decrypt, ec_decrypt, ec_encrypt, encrypt,
        generate_nonce, generate_private_public_keys, generate_secret_key, tri_hash_password,
    };
    use crate::domain::models::{
        CryptoAlgorithm, DecryptRequest, EncryptRequest, HashAlgorithm,
        PBKDF2_HMAC_SHA256_ITERATIONS,
    };

    #[test]
    fn test_should_compute_sha1() {
        let sha1 = compute_sha1("password");
        assert_eq!("5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8", sha1);
        assert_eq!(40, sha1.len());
    }

    #[test]
    fn test_should_compute_sha256() {
        let sha256 = compute_sha256("password");
        assert_eq!(
            "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8",
            sha256
        );
        assert_eq!(64, sha256.len());
    }

    #[test]
    fn test_should_compute_pbkdf2() {
        let pbkdf2 = hex::encode(compute_pbkdf2("password", b"saltsalt", "pepper", 0));
        assert_eq!(
            "0fed7eb861b1a151f8f39836575afb272ec4f57d63ed327c8eef69e834219a2a",
            pbkdf2
        );
        assert_eq!(64, pbkdf2.len());
    }

    #[test]
    fn test_should_compute_argon2() {
        // salt should be at least 8 characters
        let argon2id =
            hex::encode(compute_argon2id("password", b"saltsalt", "pepper", 64, 3, 1).unwrap());
        assert_eq!(
            "9a00ed17cf1091a0b1275c624bee3ed24eab0c68a908910b9c54d8d214f397b9",
            argon2id
        );
        assert_eq!(64, argon2id.len());
    }

    #[test]
    fn test_should_compute_hash() {
        let pbkdf2_hash = hex::encode(
            compute_hash(
                b"saltsalt",
                "pepper",
                "password",
                HashAlgorithm::Pbkdf2HmacSha256 {
                    iterations: PBKDF2_HMAC_SHA256_ITERATIONS,
                },
            )
            .unwrap(),
        );
        assert_eq!(
            "0fed7eb861b1a151f8f39836575afb272ec4f57d63ed327c8eef69e834219a2a",
            pbkdf2_hash
        );
        assert_eq!(64, pbkdf2_hash.len());

        let argon2_hash = hex::encode(
            compute_hash(
                b"saltsalt",
                "pepper",
                "password",
                HashAlgorithm::ARGON2id {
                    memory_mi_b: 64,
                    iterations: 3,
                    parallelism: 1,
                },
            )
            .unwrap(),
        );
        assert_eq!(
            "9a00ed17cf1091a0b1275c624bee3ed24eab0c68a908910b9c54d8d214f397b9",
            argon2_hash
        );
        assert_eq!(64, argon2_hash.len());
    }

    #[test]
    fn test_should_compare_password_hash() {
        let password1 = "password";
        let password2 = "passwort"; // similar to password1
        let password3 = "random";
        let hash1 = tri_hash_password(password1) as i64;
        let hash2 = tri_hash_password(password2) as i64;
        let hash3 = tri_hash_password(password3) as i64;
        assert!((hash1.clone() - hash2.clone()).abs() < 20);
        assert!((hash1 - hash3.clone()).abs() > 100);
        assert!((hash2 - hash3).abs() > 100);
    }

    #[test]
    fn test_should_encrypt_decrypt_aes_gcm() {
        let secret_key = generate_secret_key();
        let data = b"Hello, world!";

        let (nonce, ciphertext) = aes_encrypt(&secret_key, b"", data).unwrap();
        let decrypted_data = aes_decrypt(&secret_key, b"", &nonce, &ciphertext).unwrap();
        assert_eq!(data.to_vec(), decrypted_data);
    }

    #[test]
    fn test_should_encrypt_decrypt_chacha20() {
        let secret_key = generate_secret_key();
        let data = b"Hello, world!";

        let (nonce, ciphertext) = cha_encrypt(&secret_key, data).unwrap();
        let decrypted_data = cha_decrypt(&secret_key, &nonce, &ciphertext).unwrap();
        assert_eq!(data.to_vec(), decrypted_data);
    }

    #[test]
    fn test_should_encrypt_decrypt_algorithm_pbkdf2_aes256() {
        let data = "Hello, world!";
        let salt = hex::encode(generate_nonce());
        let enc_res = encrypt(EncryptRequest::new(
            &salt,
            "pepper",
            "master",
            HashAlgorithm::Pbkdf2HmacSha256 {
                iterations: PBKDF2_HMAC_SHA256_ITERATIONS,
            },
            CryptoAlgorithm::Aes256Gcm,
            data,
        ))
        .unwrap();
        let dec_res = decrypt(DecryptRequest::new(
            &salt,
            &enc_res.nonce,
            "pepper",
            "master",
            HashAlgorithm::Pbkdf2HmacSha256 {
                iterations: PBKDF2_HMAC_SHA256_ITERATIONS,
            },
            CryptoAlgorithm::Aes256Gcm,
            &enc_res.ciphertext,
        ))
        .unwrap();
        assert_eq!(data, dec_res.plaintext);
    }

    #[test]
    fn test_should_encrypt_decrypt_algorithm_pbkdf2_chacha20() {
        let data = "Hello, world!";
        let salt = hex::encode(generate_nonce());
        let enc_res = encrypt(EncryptRequest::new(
            &salt,
            "pepper",
            "master",
            HashAlgorithm::Pbkdf2HmacSha256 {
                iterations: PBKDF2_HMAC_SHA256_ITERATIONS,
            },
            CryptoAlgorithm::ChaCha20Poly1305,
            data,
        ))
        .unwrap();
        let dec_res = decrypt(DecryptRequest::new(
            &salt,
            &enc_res.nonce,
            "pepper",
            "master",
            HashAlgorithm::Pbkdf2HmacSha256 {
                iterations: PBKDF2_HMAC_SHA256_ITERATIONS,
            },
            CryptoAlgorithm::ChaCha20Poly1305,
            &enc_res.ciphertext,
        ))
        .unwrap();
        assert_eq!(data, dec_res.plaintext);
    }
    #[test]
    fn test_should_encrypt_decrypt_algorithm_argon2_aes256() {
        let data = "Hello, world!";
        let salt = hex::encode(generate_nonce());
        let enc_res = encrypt(EncryptRequest::new(
            &salt,
            "pepper",
            "master",
            HashAlgorithm::ARGON2id {
                memory_mi_b: 64,
                iterations: 3,
                parallelism: 1,
            },
            CryptoAlgorithm::Aes256Gcm,
            data,
        ))
        .unwrap();
        let dec_res = decrypt(DecryptRequest::new(
            &salt,
            &enc_res.nonce,
            "pepper",
            "master",
            HashAlgorithm::ARGON2id {
                memory_mi_b: 64,
                iterations: 3,
                parallelism: 1,
            },
            CryptoAlgorithm::Aes256Gcm,
            &enc_res.ciphertext,
        ))
        .unwrap();
        assert_eq!(data, dec_res.plaintext);
    }

    #[test]
    fn test_should_encrypt_decrypt_algorithm_argon2_chacha20() {
        let data = "Hello, world!";
        let salt = hex::encode(generate_nonce());
        let enc_res = encrypt(EncryptRequest::new(
            &salt,
            "pepper",
            "master",
            HashAlgorithm::ARGON2id {
                memory_mi_b: 64,
                iterations: 3,
                parallelism: 1,
            },
            CryptoAlgorithm::ChaCha20Poly1305,
            data,
        ))
        .unwrap();
        let dec_res = decrypt(DecryptRequest::new(
            &salt,
            &enc_res.nonce,
            "pepper",
            "master",
            HashAlgorithm::ARGON2id {
                memory_mi_b: 64,
                iterations: 3,
                parallelism: 1,
            },
            CryptoAlgorithm::ChaCha20Poly1305,
            &enc_res.ciphertext,
        ))
        .unwrap();
        assert_eq!(data, dec_res.plaintext);
    }
    #[test]
    fn test_should_generate_private_public_keys() {
        let (hex_secret, hex_public_key) = generate_private_public_keys();

        let msg = "Hello world";
        let enc = ec_encrypt(&hex_public_key, msg).unwrap();
        let dec = ec_decrypt(&hex_secret, &enc).unwrap();
        assert_eq!(msg, dec);
    }
}
