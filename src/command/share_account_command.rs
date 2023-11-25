use crate::domain::args::ArgsContext;
use crate::domain::models::{PassResult};

/// Shares an account with another user.
pub async fn execute(
    args_ctx: &ArgsContext,
    _vault_id: &str,
    account_id: &str,
    target_username: &str,
) -> PassResult<usize> {
    let size = args_ctx.service_locator
        .share_vault_account_service
        .share_account(&args_ctx.user_context, account_id, target_username)
        .await?;
    Ok(size)
}
