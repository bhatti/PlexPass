use crate::domain::args::ArgsContext;
use crate::domain::models::{PassResult};

/// UnShares a vault with another user.
pub async fn execute(
    args_ctx: &ArgsContext,
    vault_id: &str,
    target_username: &str,
) -> PassResult<usize> {
    let size = args_ctx.service_locator
        .share_vault_account_service
        .unshare_vault(&args_ctx.user_context, vault_id, target_username).await?;
    Ok(size)
}
