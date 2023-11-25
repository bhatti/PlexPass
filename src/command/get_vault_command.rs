use crate::domain::args::ArgsContext;
use crate::domain::models::{PassResult, Vault};

/// Get Vault object.
pub async fn execute(
    args_ctx: &ArgsContext,
    vault_id: &str,
    ) -> PassResult<Vault> {
    args_ctx.service_locator.vault_service.get_vault(
        &args_ctx.user_context, vault_id).await
}
