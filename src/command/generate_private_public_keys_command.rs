use crate::domain::models::{PassConfig, PassResult};
use crate::service::locator::ServiceLocator;

/// Generate private and public keys for Asymmetric encryption.
pub async fn execute(
    config: &PassConfig,
    password: &Option<String>,
) -> PassResult<(String, String)> {
    let service_locator = ServiceLocator::new(config).await?;
    let (sk, pk) = service_locator.encryption_service.generate_private_public_keys(password.clone())?;
    Ok((sk, pk))
}
