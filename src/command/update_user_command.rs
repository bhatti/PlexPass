use crate::domain::args::ArgsContext;
use crate::domain::models::{PassResult, User};

/// Update a user.
pub async fn execute(
    args_ctx: &ArgsContext,
    user: &mut User) -> PassResult<usize> {
    user.user_id = args_ctx.user.user_id.clone();
    user.version = args_ctx.user.version.clone();
    args_ctx.service_locator.user_service.update_user(
        &args_ctx.user_context, user).await
}
