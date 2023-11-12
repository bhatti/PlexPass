use std::collections::HashMap;
use crate::domain::models::{PassConfig, PassResult, Vault};
use crate::service::locator::ServiceLocator;

pub async fn execute(
    config: PassConfig,
    username: &str,
    master_password: &str,
    vault: &mut Vault,
    ) -> PassResult<usize> {
    let service_locator = ServiceLocator::new(&config).await?;
    let (ctx, _, _) = service_locator.user_service.signin_user(username, master_password, HashMap::new()).await?;
    let old_vault = service_locator.vault_service.get_vault(&ctx, &vault.vault_id).await?;
    vault.owner_user_id = old_vault.owner_user_id.clone();
    vault.version = old_vault.version;
    let size = service_locator.vault_service.update_vault(&ctx, vault).await?;
    Ok(size)
}
