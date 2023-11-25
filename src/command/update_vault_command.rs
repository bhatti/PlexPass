use crate::domain::args::ArgsContext;
use crate::domain::models::{PassResult, Vault};

/// Update a vault.
pub async fn execute(
    args_ctx: &ArgsContext,
    vault: &mut Vault,
    ) -> PassResult<usize> {
    let old_vault = args_ctx.service_locator.vault_service.get_vault(
        &args_ctx.user_context, &vault.vault_id).await?;
    vault.owner_user_id = old_vault.owner_user_id.clone();
    vault.version = old_vault.version;
    let size = args_ctx.service_locator.vault_service.update_vault(
        &args_ctx.user_context, vault).await?;
    Ok(size)
}
