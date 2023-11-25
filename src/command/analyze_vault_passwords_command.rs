use crate::domain::args::ArgsContext;
use crate::domain::models::{PassResult, VaultAnalysis};

/// Analyze passwords for given vault.
pub async fn execute(
    args_ctx: &ArgsContext,
    vault_id: &str,
) -> PassResult<VaultAnalysis> {
    args_ctx.service_locator.password_service.analyze_vault_passwords(
        &args_ctx.user_context, vault_id).await
}
