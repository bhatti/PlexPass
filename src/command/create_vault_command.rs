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
    vault.owner_user_id = ctx.user_id.clone();
    service_locator.vault_service.create_vault(&ctx, &vault).await
}
