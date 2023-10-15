use std::sync::Arc;

use crate::domain::models::{HSMProvider, PassConfig, PassResult};
use crate::store::hsm_store_file::EncryptedFileHSMStore;
use crate::store::hsm_store_keychain::KeychainHSMStore;
use crate::store::HSMStore;

pub(crate) fn create_hsm_store(config: &PassConfig) -> PassResult<Arc<dyn HSMStore + Send + Sync>> {
    Ok(match config.hsm_provider() {
        HSMProvider::EncryptedFile => Arc::new(EncryptedFileHSMStore::new(config)?),
        HSMProvider::Keychain => Arc::new(KeychainHSMStore::new()),
    })
}
