use std::collections::HashMap;
use crate::domain::models::{PassConfig, PassResult, User};
use crate::service::locator::ServiceLocator;

pub async fn execute(
    config: PassConfig,
    username: &str,
    master_password: &str,
    id: Option<String>) -> PassResult<User> {
    let service_locator = ServiceLocator::new(&config).await?;
    let (ctx, user, _) = service_locator.user_service.signin_user(username, master_password, HashMap::new()).await?;
    if let Some(id) = id {
        let (_, user) = service_locator.user_service.get_user(&ctx, &id).await?;
        Ok(user)
    } else {
        Ok(user)
    }
}
