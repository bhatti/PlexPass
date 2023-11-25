use crate::domain::args::ArgsContext;
use crate::domain::models::{LookupKind, PassResult};

/// Delete lookup entry.
pub async fn execute(
    args_ctx: &ArgsContext,
    name: &str,
) -> PassResult<usize> {
    args_ctx.service_locator
        .lookup_service
        .delete_lookup(
            &args_ctx.user_context, LookupKind::CATEGORY, name)
        .await
}
