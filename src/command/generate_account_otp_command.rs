use crate::controller::models::AccountResponse;
use crate::domain::args::ArgsContext;
use crate::domain::models::{PassResult};

/// Generate an otp for account.
pub async fn execute(
    args_ctx: &ArgsContext,
    account_id: &str,
) -> PassResult<u32> {
    let account = AccountResponse::new(
        &args_ctx.service_locator.account_service.get_account(
            &args_ctx.user_context, account_id).await?);
    Ok(account.generated_otp.unwrap_or(0))
}
