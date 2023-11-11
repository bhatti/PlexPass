use crate::domain::models::{PassConfig, PassResult};
use crate::service::locator::ServiceLocator;

pub async fn execute(
    config: PassConfig,
    email : &str,
    hibp_api_key: &Option<String>
) -> PassResult<String> {
    let config = if let Some(hibp_api_key) = hibp_api_key {
        let mut config = config.clone();
        config.hibp_api_key = Some(hibp_api_key.to_string());
        config
    } else {
        config
    };
    let service_locator = ServiceLocator::new(&config).await?;
    service_locator.password_service.email_compromised(email).await
}
