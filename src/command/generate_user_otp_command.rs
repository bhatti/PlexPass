use crate::domain::args::ArgsContext;
use crate::domain::models::{PassResult};

/// Generate an otp for user.
pub async fn execute(
    args_ctx: &ArgsContext,
    otp_secret : &Option<String>,
) -> PassResult<u32> {
    if let Some(otp_secret) = otp_secret {
        return args_ctx.service_locator.otp_service.generate_otp(
            otp_secret).await;
    }
    args_ctx.service_locator.user_service.generate_user_otp(
        &args_ctx.user_context).await
}
