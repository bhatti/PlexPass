use crate::domain::args::ArgsContext;
use crate::domain::models::{PassResult};

/// Shares a vault with another user.
pub async fn execute(
    args_ctx: &ArgsContext,
    vault_id: &str,
    target_username: &str,
    read_only: &Option<bool>,
) -> PassResult<usize> {
    let size = args_ctx.service_locator
        .share_vault_account_service
        .share_vault(&args_ctx.user_context, vault_id, target_username, read_only.unwrap_or(false))
        .await?;
    Ok(size)
}
