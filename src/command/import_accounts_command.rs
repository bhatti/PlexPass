use std::fs;
use std::path::PathBuf;
use crate::domain::args::ArgsContext;
use crate::domain::models::{EncodingScheme, ImportResult, PassResult, ProgressStatus};

/// Import accounts to a user vault.
pub async fn execute(
    args_ctx: &ArgsContext,
    vault_id: &Option<String>,
    password: &Option<String>,
    in_path: &PathBuf,
) -> PassResult<ImportResult> {
    let data = fs::read(in_path)?;
    let res = args_ctx.service_locator.import_export_service.import_accounts(
        &args_ctx.user_context,
        vault_id.clone(),
        None,
        password.clone(),
        EncodingScheme::Base64,
        &data,
        Box::new(|status| match status {
            ProgressStatus::Started { .. } => {}
            ProgressStatus::Updated { .. } => {}
            ProgressStatus::Completed => {}
            ProgressStatus::Failed(_) => {}
        }),
    ).await?;
    Ok(res)
}
