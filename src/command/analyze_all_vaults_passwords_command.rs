use std::collections::HashMap;
use crate::domain::models::{PassConfig, PassResult, VaultAnalysis};
use crate::service::locator::ServiceLocator;

pub async fn execute(
    config: PassConfig,
    username: &str,
    master_password: &str,
) -> PassResult<HashMap<String, VaultAnalysis>> {
    let service_locator = ServiceLocator::new(&config).await?;
    let (ctx, _, _) = service_locator.user_service.signin_user(
        username, master_password, HashMap::new()).await?;
    service_locator.password_service.analyze_all_vault_passwords(&ctx).await
}
