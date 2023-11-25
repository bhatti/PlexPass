use std::fs;
use std::path::PathBuf;
use crate::domain::args::ArgsContext;
use crate::domain::models::{EncodingScheme, PassResult, ProgressStatus};

/// Export all accounts in a vault to a file that can be protected with a password.
pub async fn execute(
    args_ctx: &ArgsContext,
    vault_id: &str,
    password: &Option<String>,
    out_path: &PathBuf,
) -> PassResult<usize> {
    let (_, bytes_csv) = args_ctx.service_locator.import_export_service.export_accounts(
        &args_ctx.user_context,
        vault_id,
        password.clone(),
        EncodingScheme::Base64,
        Box::new(|status| match status {
            ProgressStatus::Started { .. } => {}
            ProgressStatus::Updated { .. } => {}
            ProgressStatus::Completed => {}
            ProgressStatus::Failed(_) => {}
        }),
    ).await?;
    let len = &bytes_csv.len();
    fs::write(out_path, bytes_csv)?;
    Ok(*len)
}
