use std::collections::HashMap;
use crate::domain::models::{PassConfig, PassResult, User};
use crate::service::locator::ServiceLocator;

pub async fn execute(
    config: PassConfig,
    user: &mut User,
    master_password: &str) -> PassResult<usize> {
    let service_locator = ServiceLocator::new(&config).await?;
    let (ctx, signin_user, _) = service_locator.user_service.signin_user(&user.username, master_password, HashMap::new()).await?;
    user.user_id = signin_user.user_id.clone();
    user.version = signin_user.version;
    service_locator.user_service.update_user(&ctx, user).await
}
