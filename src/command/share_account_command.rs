use std::collections::HashMap;
use crate::domain::models::{PassConfig, PassResult};
use crate::service::locator::ServiceLocator;

pub async fn execute(
    config: PassConfig,
    username: &str,
    master_password: &str,
    _vault_id: &str,
    account_id: &str,
    target_username: &str,
) -> PassResult<usize> {
    let service_locator = ServiceLocator::new(&config).await?;
    let (ctx, _, _) = service_locator.user_service.signin_user(username, master_password, HashMap::new()).await?;
    let size = service_locator
        .share_vault_account_service
        .share_account(&ctx, account_id, target_username)
        .await?;
    Ok(size)
}
