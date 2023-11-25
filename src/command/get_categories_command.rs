use crate::domain::args::ArgsContext;
use crate::domain::models::{LookupKind, PassResult};

/// Find lookup entries.
pub async fn execute(
    args_ctx: &ArgsContext,
) -> PassResult<Vec<String>> {
    let categories: Vec<String> = args_ctx.service_locator
        .lookup_service
        .get_lookups(&args_ctx.user_context, LookupKind::CATEGORY)
        .await?
        .into_iter()
        .map(|l| l.name.to_string())
        .collect();
    Ok(categories)
}
