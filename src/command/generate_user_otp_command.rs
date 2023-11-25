use crate::domain::args::ArgsContext;
use crate::domain::models::{PassResult};

/// Generate an otp for user.
pub async fn execute(
    args_ctx: &ArgsContext,
) -> PassResult<u32> {
    args_ctx.service_locator.user_service.generate_user_otp(
        &args_ctx.user_context).await
}
