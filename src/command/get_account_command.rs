use crate::controller::models::AccountResponse;
use crate::domain::args::ArgsContext;
use crate::domain::models::{PassResult};

/// Find an account.
pub async fn execute(
    args_ctx: &ArgsContext,
    account_id: &str,
) -> PassResult<AccountResponse> {
    Ok(AccountResponse::new(
        &args_ctx.service_locator.account_service.get_account(
            &args_ctx.user_context, account_id).await?))
}
