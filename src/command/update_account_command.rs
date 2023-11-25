use crate::domain::args::ArgsContext;
use crate::domain::models::{Account, PassResult};

/// Update an account.
pub async fn execute(
    args_ctx: &ArgsContext,
    account: &mut Account,
) -> PassResult<usize> {
    let old_account = args_ctx.service_locator.account_service.get_account(
        &args_ctx.user_context, &account.details.account_id).await?;
    account.details.version = old_account.details.version;
    let size = args_ctx.service_locator.account_service.update_account(
        &args_ctx.user_context, account).await?;
    Ok(size)
}
