use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use crate::domain::models::{EncodingScheme, ImportResult, PassConfig, PassResult, ProgressStatus};
use crate::service::locator::ServiceLocator;

pub async fn execute(
    config: PassConfig,
    username: &str,
    master_password: &str,
    vault_id: &Option<String>,
    password: &Option<String>,
    in_path: &PathBuf,
) -> PassResult<ImportResult> {
    let service_locator = ServiceLocator::new(&config).await?;
    let (ctx, _, _) = service_locator.user_service.signin_user(username, master_password, HashMap::new()).await?;
    let data = fs::read(in_path)?;
    let res = service_locator.import_export_service.import_accounts(
        &ctx,
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
