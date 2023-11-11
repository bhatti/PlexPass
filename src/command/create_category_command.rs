use std::collections::HashMap;
use crate::domain::models::{Lookup, LookupKind, PassConfig, PassResult};
use crate::service::locator::ServiceLocator;

pub async fn execute(
    config: PassConfig,
    username: &str,
    master_password: &str,
    name: &str,
) -> PassResult<usize> {
    let service_locator = ServiceLocator::new(&config).await?;
    let (ctx, _, _) = service_locator.user_service.signin_user(username, master_password, HashMap::new()).await?;
    let lookup = Lookup::new(&ctx.user_id, LookupKind::CATEGORY, name);
    service_locator
        .lookup_service
        .create_lookup(&ctx, &lookup)
        .await
}
