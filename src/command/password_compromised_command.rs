use crate::domain::models::{PassConfig, PassResult};
use crate::service::locator::ServiceLocator;

/// Check if a password is compromised.
pub async fn execute(
    config: PassConfig,
    password: &str,
) -> PassResult<bool> {
    let service_locator = ServiceLocator::new(&config).await?;
    service_locator.password_service.password_compromised(password).await
}
