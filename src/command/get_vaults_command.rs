use crate::domain::args::ArgsContext;
use crate::domain::models::{PassResult, Vault};

/// Get User vaults.
pub async fn execute(
    args_ctx: &ArgsContext,
) -> PassResult<Vec<Vault>> {
    args_ctx.service_locator.vault_service.get_user_vaults(
        &args_ctx.user_context).await
}
