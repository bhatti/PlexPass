use crate::domain::args::ArgsContext;
use crate::domain::models::{PassResult};

/// Delete an account.
pub async fn execute(
    args_ctx: &ArgsContext,
    account_id: &str,
) -> PassResult<usize> {
    args_ctx.service_locator.account_service.delete_account(
        &args_ctx.user_context, account_id).await
}
