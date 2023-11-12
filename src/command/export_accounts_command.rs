use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use crate::domain::models::{EncodingScheme, PassConfig, PassResult, ProgressStatus};
use crate::service::locator::ServiceLocator;

pub async fn execute(
    config: PassConfig,
    username: &str,
    master_password: &str,
    vault_id: &str,
    password: &Option<String>,
    out_path: &PathBuf,
) -> PassResult<usize> {
    let service_locator = ServiceLocator::new(&config).await?;
    let (ctx, _, _) = service_locator.user_service.signin_user(username, master_password, HashMap::new()).await?;
    let (_, bytes_csv) = service_locator.import_export_service.export_accounts(
        &ctx,
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
