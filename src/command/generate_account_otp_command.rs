use crate::controller::models::AccountResponse;
use crate::domain::args::ArgsContext;
use crate::domain::models::{PassResult};

/// Generate an otp for account.
pub async fn execute(
    args_ctx: &ArgsContext,
    account_id: &Option<String>,
    otp_secret : &Option<String>,
) -> PassResult<u32> {
    if let Some(otp_secret) = otp_secret {
        return args_ctx.service_locator.otp_service.generate_otp(
            otp_secret).await;
    }

    if let Some(account_id) = account_id {
        let account = AccountResponse::new(
            &args_ctx.service_locator.account_service.get_account(
                &args_ctx.user_context, account_id).await?);
        return Ok(account.generated_otp.unwrap_or(0));
    }
    Ok(0)
}
