use crate::domain::args::ArgsContext;
use crate::domain::models::{PassResult};

/// Delete a user.
pub async fn execute(
    args_ctx: &ArgsContext,
    id: Option<String>) -> PassResult<usize> {
    if let Some(id) = id {
        args_ctx.service_locator.user_service.delete_user(&args_ctx.user_context, &id).await
    } else {
        args_ctx.service_locator.user_service.delete_user(&args_ctx.user_context, &args_ctx.user.user_id).await
    }
}
