use crate::domain::models::{PassConfig, PassResult, PasswordInfo};
use crate::service::locator::ServiceLocator;

/// Checks password strength.
pub async fn execute(
    config: PassConfig,
    password: &str,
) -> PassResult<PasswordInfo> {
    let service_locator = ServiceLocator::new(&config).await?;
    service_locator.password_service.password_info(password).await
}
