use crate::domain::error::PassError;
use crate::domain::models::PassResult;
use crate::store::HSMStore;

const KEY_CHAIN_SERVICE_NAME: &str = "PlexPass";

pub struct KeychainHSMStore {}

impl KeychainHSMStore {
    pub fn new() -> KeychainHSMStore {
        Self {}
    }
}

impl HSMStore for KeychainHSMStore {
    #[cfg(target_os = "macos")]
    fn get_property(&self, username: &str, name: &str) -> PassResult<String> {
        let full_name = format!("{}_{}", username, name);
        let keychain = security_framework::os::macos::keychain::SecKeychain::default()?;

        // Retrieve key data from the keychain.
        match keychain.find_generic_password(KEY_CHAIN_SERVICE_NAME, &full_name) {
            Ok((item, _)) => Ok(std::str::from_utf8(&item)?.to_string()),
            Err(err) => Err(PassError::crypto(
                format!("failed to get hsm property {} due to {:?}", &full_name, err).as_str(),
            )),
        }
    }

    #[cfg(not(target_os = "macos"))]
    fn get_property(&self, _username: &str, _name: &str) -> PassResult<String> {
        Err(PassError::runtime("Keychain is only supported on macos", None))
    }

    #[cfg(target_os = "macos")]
    fn set_property(&self, username: &str, name: &str, value: &str) -> PassResult<()> {
        let full_name = format!("{}_{}", username, name);
        let keychain = security_framework::os::macos::keychain::SecKeychain::default()?;
        // Store key data in the keychain.
        keychain.set_generic_password(KEY_CHAIN_SERVICE_NAME, &full_name, value.as_bytes())?;
        Ok(())
    }

    #[cfg(not(target_os = "macos"))]
    fn set_property(&self, _username: &str, _name: &str, _value: &str) -> PassResult<()> {
        Err(PassError::runtime("Keychain is only supported on macos", None))
    }
}

#[cfg(target_os = "macos")]
impl From<security_framework::base::Error> for PassError {
    fn from(err: security_framework::base::Error) -> Self {
        PassError::crypto(format!("keychain failed {:?}", err).as_str())
    }
}


#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn test_should_get_set_hsm_property() {
        //let mut hsm = KeychainHSMStore::new();
        // let _ = hsm.set_property("user1_key1", "value1").unwrap();
        // let value = hsm.get_property("user1_key1").unwrap();
        // assert_eq!("value1", value);
    }
}
