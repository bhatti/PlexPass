use crate::domain::args::ArgsContext;
use crate::domain::models::{PassResult};

/// Searches users
pub async fn execute(
    args_ctx: &ArgsContext,
    q: &str,
) -> PassResult<Vec<String>> {
    args_ctx.service_locator.share_vault_account_service.lookup_usernames(
        &args_ctx.user_context, q).await
}
