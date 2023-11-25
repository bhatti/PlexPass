use std::fs;
use std::path::PathBuf;
use crate::domain::models::{EncodingScheme, PassConfig, PassResult};
use crate::service::locator::ServiceLocator;

/// Symmetric encryption.
pub async fn execute(
    config: &PassConfig,
    symmetric_key: &str,
    in_path: &PathBuf,
    out_path: &PathBuf,
) -> PassResult<()> {
    let service_locator = ServiceLocator::new(config).await?;
    let data = fs::read(in_path)?;
    let res = service_locator.encryption_service.symmetric_encrypt(
        "",
        "",
        symmetric_key,
        data,
        EncodingScheme::Base64)?;
    fs::write(out_path, res)?;
    Ok(())
}
