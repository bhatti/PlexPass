use std::fs;
use std::path::PathBuf;
use crate::domain::models::{EncodingScheme, PassConfig, PassResult};
use crate::service::locator::ServiceLocator;

/// Asymmetric encryption command.
pub async fn execute(
    config: &PassConfig,
    public_key: &str,
    in_path: &PathBuf,
    out_path: &PathBuf,
) -> PassResult<()> {
    let service_locator = ServiceLocator::new(config).await?;
    let data = fs::read(in_path)?;
    let res = service_locator.encryption_service.asymmetric_encrypt(
        public_key,
        data,
        EncodingScheme::Base64)?;
    fs::write(out_path, res)?;
    Ok(())
}
