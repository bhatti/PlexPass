use std::collections::HashMap;
use crate::domain::models::{Account, PassConfig, PassResult};
use crate::service::locator::ServiceLocator;

pub async fn execute(
    config: PassConfig,
    master_username: &str,
    master_password: &str,
    vault_id: &str,
    q: Option<String>,
) -> PassResult<Vec<Account>> {
    let service_locator = ServiceLocator::new(&config).await?;
    let (ctx, _, _) = service_locator.user_service.signin_user(master_username, master_password, HashMap::new()).await?;
    let account_summaries = service_locator.vault_service.account_summaries_by_vault(&ctx, vault_id, q).await?;
    let mut full_accounts = vec![];
    for account_summary in &account_summaries {
        if account_summaries.len() <= 10 {
            full_accounts.push(service_locator.account_service.get_account(&ctx, &account_summary.account_id).await?);
        } else {
            if full_accounts.len() == 0 {
                log::warn!("Too many accounts queried {}, showing only summaries", account_summaries.len());
            }
            let mut account = Account::new(vault_id, account_summary.kind.clone());
            account.details = account_summary.clone();
            full_accounts.push(account);
        }
    }
    Ok(full_accounts)
}
