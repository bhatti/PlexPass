use crate::domain::models::{PassConfig, PassResult, PasswordPolicy};
use crate::service::locator::ServiceLocator;

/// Generate a password.
pub async fn execute(
    config: PassConfig,
    policy: &PasswordPolicy,
) -> PassResult<Option<String>> {
    let service_locator = ServiceLocator::new(&config).await?;
    Ok(service_locator.password_service.generate_password(policy).await)
}
