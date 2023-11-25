use std::collections::HashMap;
use crate::dao::models::UserContext;
use crate::domain::models::{PassConfig, PassResult, User};
use crate::service::locator::ServiceLocator;

/// Create and register a new user.
pub async fn execute(
    config: &PassConfig,
    user: &User,
    master_password: &str) -> PassResult<UserContext> {
    let service_locator = ServiceLocator::new(config).await?;
    service_locator.user_service.register_user(user, master_password, HashMap::new()).await
}
