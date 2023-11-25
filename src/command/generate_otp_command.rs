use crate::domain::models::{PassConfig, PassResult};
use crate::service::locator::ServiceLocator;

/// Generate an otp for secret
pub async fn execute(
    config: &PassConfig,
    otp_secret: &str,
) -> PassResult<u32> {
    let service_locator = ServiceLocator::new(config).await?;
    service_locator.otp_service.generate_otp(
        otp_secret).await
}
