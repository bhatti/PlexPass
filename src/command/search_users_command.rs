use std::collections::HashMap;
use crate::domain::models::{PassConfig, PassResult};
use crate::service::locator::ServiceLocator;

pub async fn execute(
    config: PassConfig,
    username: &str,
    master_password: &str,
    q: &str,
) -> PassResult<Vec<String>> {
    let service_locator = ServiceLocator::new(&config).await?;
    let (ctx, _, _) = service_locator.user_service.signin_user(username, master_password, HashMap::new()).await?;
    service_locator.share_vault_account_service.lookup_usernames(&ctx, q).await
}
