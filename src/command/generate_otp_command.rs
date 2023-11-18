use std::collections::HashMap;
use crate::controller::models::AccountResponse;
use crate::domain::models::{PassConfig, PassResult};
use crate::service::locator::ServiceLocator;

pub async fn execute(
    config: PassConfig,
    master_username: &str,
    master_password: &str,
    account_id: &Option<String>,
    otp_secret : &Option<String>,
) -> PassResult<u32> {
    let service_locator = ServiceLocator::new(&config).await?;
    let (ctx, _, _) = service_locator.user_service.signin_user(master_username, master_password, HashMap::new()).await?;
    if let Some(otp_secret) = otp_secret {
        return Ok(service_locator.otp_service.generate(&ctx, &otp_secret).await?);
    }
    if let Some(account_id) = account_id {
        let account = AccountResponse::new(&service_locator.account_service.get_account(&ctx, account_id).await?);
        return Ok(account.generated_otp.unwrap_or(0));
    }
    Ok(0)
}
