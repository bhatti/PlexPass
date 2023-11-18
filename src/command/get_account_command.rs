use std::collections::HashMap;
use crate::controller::models::AccountResponse;
use crate::domain::models::{PassConfig, PassResult};
use crate::service::locator::ServiceLocator;

pub async fn execute(
    config: PassConfig,
    master_username: &str,
    master_password: &str,
    account_id: &str,
) -> PassResult<AccountResponse> {
    let service_locator = ServiceLocator::new(&config).await?;
    let (ctx, _, _) = service_locator.user_service.signin_user(master_username, master_password, HashMap::new()).await?;
    Ok(AccountResponse::new(&service_locator.account_service.get_account(&ctx, account_id).await?))
}
