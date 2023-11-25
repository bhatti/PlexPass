use crate::domain::args::ArgsContext;
use crate::domain::models::{Lookup, LookupKind, PassResult};

/// Create lookup entry.
pub async fn execute(
    args_ctx: &ArgsContext,
    name: &str,
) -> PassResult<usize> {
    let lookup = Lookup::new(
        &args_ctx.user.user_id, LookupKind::CATEGORY, name);
    args_ctx.service_locator
        .lookup_service
        .create_lookup(&args_ctx.user_context, &lookup)
        .await
}
