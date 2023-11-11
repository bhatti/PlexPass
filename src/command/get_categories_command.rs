use std::collections::HashMap;
use crate::domain::models::{LookupKind, PassConfig, PassResult};
use crate::service::locator::ServiceLocator;

pub async fn execute(
    config: PassConfig,
    username: &str,
    master_password: &str,
) -> PassResult<Vec<String>> {
    let service_locator = ServiceLocator::new(&config).await?;
    let (ctx, _, _) = service_locator.user_service.signin_user(username, master_password, HashMap::new()).await?;
    let categories: Vec<String> = service_locator
        .lookup_service
        .get_lookups(&ctx, LookupKind::CATEGORY)
        .await?
        .into_iter()
        .map(|l| l.name.to_string())
        .collect();
    Ok(categories)
}
