use crate::domain::args::ArgsContext;
use crate::domain::models::{PassResult, Vault};

/// Create a vault.
pub async fn execute(
    args_ctx: &ArgsContext,
    vault: &mut Vault,
    ) -> PassResult<usize> {
    vault.owner_user_id = args_ctx.user.user_id.clone();
    args_ctx.service_locator.vault_service.create_vault(
        &args_ctx.user_context, vault).await
}
