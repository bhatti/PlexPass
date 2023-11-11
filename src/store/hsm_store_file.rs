use crate::crypto;
use crate::domain::models::{PassConfig, PassResult};
use crate::store::HSMStore;
use std::fs::File;
use std::io::{Read, Write};

const KEY_FILE_NAME: &str = "enc_key.dat";

// For non-macos - requires DEVICE_PEPPER_KEY at startup
pub(crate) struct EncryptedFileHSMStore {
    config: PassConfig,
    sk_pk: (String, String),
}

impl EncryptedFileHSMStore {
    pub(crate) fn new(config: &PassConfig) -> PassResult<EncryptedFileHSMStore> {
        Ok(Self {
            config: config.clone(),
            sk_pk: crypto::generate_private_public_keys_from_secret(&config.device_pepper_key)?,
        })
    }

    fn build_file_name(&self, username: &str, name: &str) -> String {
        let file_name = self
            .config
            .build_data_file(&format!("{}_{}_{}", crypto::compute_sha256_hex(username), name, KEY_FILE_NAME));
        file_name
    }
}

impl HSMStore for EncryptedFileHSMStore {
    fn get_property(&self, username: &str, name: &str) -> PassResult<String> {
        let file_name = self.build_file_name(username, name);
        let mut data_file = File::open(file_name)?;
        let mut file_content = String::new();
        data_file.read_to_string(&mut file_content)?;
        crypto::ec_decrypt_hex(&self.sk_pk.0, &file_content)
    }

    fn set_property(&self, username: &str, name: &str, value: &str) -> PassResult<()> {
        let file_name = self.build_file_name(username, name);
        let mut data_file = File::create(file_name)?;
        let encrypted = crypto::ec_encrypt_hex(&self.sk_pk.1, value)?;
        data_file.write(&encrypted.as_bytes())?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::domain::models::PassConfig;
    use crate::store::hsm_store_file::EncryptedFileHSMStore;
    use crate::store::HSMStore;

    #[tokio::test]
    async fn test_should_get_set_hsm_property() {
        // GIVEN hsm store, setting repository and user repository
        //let mut hsm = KeychainHSMStore::new();
        let config = PassConfig::new();
        let hsm = EncryptedFileHSMStore::new(&config).unwrap();

        // WHEN setting hsm property
        let _ = hsm
            .set_property("username", "user1_key1", "value1")
            .unwrap();
        let value = hsm.get_property("username", "user1_key1").unwrap();
        assert_eq!("value1", value);
    }
}
