use crate::controller::models::UserResponse;
use crate::domain::args::ArgsContext;
use crate::domain::models::{PassResult};

/// Get a user object.
pub async fn execute(
    args_ctx: &ArgsContext,
    id: Option<String>) -> PassResult<UserResponse> {
    if let Some(id) = id {
        let (_, user) = args_ctx.service_locator.user_service.get_user(
            &args_ctx.user_context, &id).await?;
        Ok(UserResponse::new(&user))
    } else {
        Ok(UserResponse::new(&args_ctx.user))
    }
}
