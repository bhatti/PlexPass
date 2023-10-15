use crate::domain::models::PassResult;

pub(crate) mod factory;
pub(crate) mod hsm_store_file;
mod hsm_store_keychain;

pub trait HSMStore {
    // get_property finds a secured property of user by name from the keychain.
    fn get_property(&self, username: &str, name: &str) -> PassResult<String>;

    // set_property sets a secured property of user by name and value into the keychain.
    fn set_property(&self, username: &str, name: &str, value: &str) -> PassResult<()>;
}
