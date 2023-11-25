use std::fs;
use std::path::PathBuf;
use crate::domain::args::ArgsContext;
use crate::domain::models::{EncodingScheme, PassResult};

/// Asymmetric encryption command using target username.
pub async fn execute(
    args_ctx: &ArgsContext,
    target_username: &str,
    in_path: &PathBuf,
    out_path: &PathBuf,
) -> PassResult<()> {
    let data = fs::read(in_path)?;
    let res = args_ctx.service_locator.user_service.asymmetric_user_encrypt(
        &args_ctx.user_context,
        target_username,
        data,
        EncodingScheme::Base64).await?;
    fs::write(out_path, res)?;
    Ok(())
}
