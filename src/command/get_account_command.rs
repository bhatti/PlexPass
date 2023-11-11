use std::collections::HashMap;
use crate::domain::models::{Account, PassConfig, PassResult};
use crate::service::locator::ServiceLocator;

pub async fn execute(
    config: PassConfig,
    master_username: &str,
    master_password: &str,
    account_id: &str,
) -> PassResult<Account> {
    let service_locator = ServiceLocator::new(&config).await?;
    let (ctx, _, _) = service_locator.user_service.signin_user(master_username, master_password, HashMap::new()).await?;
    service_locator.account_service.get_account(&ctx, &account_id).await
}
