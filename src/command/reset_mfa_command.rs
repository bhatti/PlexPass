use crate::domain::args::ArgsContext;
use crate::domain::models::{PassResult};

/// Reset MFA settings.
pub async fn execute(
    args_ctx: &ArgsContext,
    recovery_code: &str,
) -> PassResult<()> {
    args_ctx.service_locator.auth_service.reset_mfa_keys(
        &args_ctx.user_context,
        recovery_code,
        &args_ctx.session_id).await
}
