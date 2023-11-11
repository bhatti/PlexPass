use std::collections::HashMap;
use crate::domain::models::{PassConfig, PassResult};
use crate::service::locator::ServiceLocator;

pub async fn execute(
    config: PassConfig,
    username: &str,
    master_password: &str,
    id: Option<String>) -> PassResult<usize> {
    let service_locator = ServiceLocator::new(&config).await?;
    let (ctx, _, _) = service_locator.user_service.signin_user(username, master_password, HashMap::new()).await?;
    if let Some(id) = id {
        service_locator.user_service.delete_user(&ctx, &id).await
    } else {
        service_locator.user_service.delete_user(&ctx, &ctx.user_id).await
    }
}
