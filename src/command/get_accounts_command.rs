use crate::controller::models::AccountResponse;
use crate::domain::args::ArgsContext;
use crate::domain::models::{Account, PassResult};

/// Get all accounts in a vault that match string.
pub async fn execute(
    args_ctx: &ArgsContext,
    vault_id: &str,
    q: Option<String>,
) -> PassResult<Vec<AccountResponse>> {
    let account_summaries = args_ctx.service_locator.vault_service.account_summaries_by_vault(
        &args_ctx.user_context, vault_id, q).await?;
    let mut full_accounts = vec![];
    for account_summary in &account_summaries {
        if account_summaries.len() <= 10 {
            full_accounts.push(AccountResponse::new(
                &args_ctx.service_locator.account_service.get_account(
                    &args_ctx.user_context, &account_summary.account_id).await?));
        } else {
            if full_accounts.is_empty() {
                log::warn!("Too many accounts queried {}, showing only summaries", account_summaries.len());
            }
            let mut account = Account::new(vault_id, account_summary.kind.clone());
            account.details = account_summary.clone();
            full_accounts.push(AccountResponse::new(&account));
        }
    }
    Ok(full_accounts)
}
