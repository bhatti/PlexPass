use crate::domain::args::ArgsContext;
use crate::domain::models::{PassResult};

/// Change user password.
pub async fn execute(
    args_ctx: &ArgsContext,
    old_password: &str,
    new_password: &str,
    confirm_new_password: &str,
) -> PassResult<usize> {
    args_ctx.service_locator.auth_service.change_password(
            &args_ctx.user_context,
            old_password,
            new_password,
            confirm_new_password,
            &args_ctx.session_id).await
}
