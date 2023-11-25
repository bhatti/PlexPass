use crate::domain::args::ArgsContext;
use crate::domain::models::{PassResult};

/// Delete a vault.
pub async fn execute(
    args_ctx: &ArgsContext,
    vault_id: &str,
) -> PassResult<usize> {
    args_ctx.service_locator.vault_service.delete_vault(
        &args_ctx.user_context, vault_id).await
}
