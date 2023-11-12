use std::collections::HashMap;
use crate::dao::models::UserContext;
use crate::domain::models::{PassConfig, PassResult, User, UserToken};
use crate::service::locator::ServiceLocator;

pub async fn execute(
    config: PassConfig,
    user: &User,
    master_password: &str) -> PassResult<(UserContext, UserToken)> {
    let service_locator = ServiceLocator::new(&config).await?;
    service_locator.user_service.signup_user(user, master_password, HashMap::new()).await
}
