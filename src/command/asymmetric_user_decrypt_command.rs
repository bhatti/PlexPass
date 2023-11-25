use std::fs;
use std::path::PathBuf;
use crate::domain::args::ArgsContext;
use crate::domain::models::{EncodingScheme, PassResult};

/// Asymmetric decryption command using user private key.
pub async fn execute(
    args_ctx: &ArgsContext,
    in_path: &PathBuf,
    out_path: &PathBuf,
) -> PassResult<()> {
    let data = fs::read(in_path)?;
    let res = args_ctx.service_locator.user_service.asymmetric_user_decrypt(
        &args_ctx.user_context,
        data,
        EncodingScheme::Base64).await?;
    fs::write(out_path, res)?;
    Ok(())
}
