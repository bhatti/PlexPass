use crate::domain::args::ArgsContext;
use crate::domain::models::{Account, PassResult};

/// Create account.
pub async fn execute(
    args_ctx: &ArgsContext,
    account: &Account,
    ) -> PassResult<usize> {
    let size = args_ctx.service_locator.account_service.create_account(
        &args_ctx.user_context, account).await?;
    Ok(size)
}
