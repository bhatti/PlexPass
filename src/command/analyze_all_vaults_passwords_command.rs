use std::collections::HashMap;
use crate::domain::args::ArgsContext;
use crate::domain::models::{PassResult, VaultAnalysis};

/// Analyze all vaults for password vulnerabilities.
pub async fn execute(
    args_ctx: &ArgsContext,
) -> PassResult<HashMap<String, VaultAnalysis>> {
    args_ctx.service_locator.password_service.analyze_all_vault_passwords(
        &args_ctx.user_context).await
}
