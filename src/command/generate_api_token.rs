use crate::domain::args::ArgsContext;
use crate::domain::models::{PassResult, UserToken};

/// Generate an otp for user.
pub async fn execute(
    args_ctx: &ArgsContext,
    jwt_max_age_minutes: &Option<i64>,
) -> PassResult<UserToken> {
    Ok(UserToken::from_context(
        &args_ctx.session_id,
        &args_ctx.user_context,
        jwt_max_age_minutes.unwrap_or(args_ctx.config.jwt_max_age_minutes)))
}
