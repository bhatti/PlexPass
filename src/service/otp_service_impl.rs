use std::fs;
use std::path::Path;

use async_trait::async_trait;
use chrono::Utc;
use image::{ImageBuffer, Luma};
use otpauth::TOTP;
use prometheus::Registry;
use qrcode::QrCode;
use url::Url;

use crate::controller::models::AccountResponse;
use crate::dao::models::UserContext;
use crate::domain::models::{Account, AccountKind, PassConfig, PassResult};
use crate::service::OTPService;
use crate::utils::metrics::PassMetrics;

#[derive(Clone)]
pub(crate) struct OTPServiceImpl {
    metrics: PassMetrics,
}

impl OTPServiceImpl {
    pub(crate) fn new(
        _config: &PassConfig,
        registry: &Registry,
    ) -> PassResult<Self> {
        Ok(Self {
            metrics: PassMetrics::new("otp_service", registry)?,
        })
    }

    #[allow(dead_code)]
    async fn decode_otp(content: &str) -> PassResult<Vec<AccountResponse>> {
        let mut accounts = Vec::new();
        // Split the content and parse each URI
        let uris = content.split('\n');

        // otpauth://TYPE/LABEL?PARAMETERS
        for uri in uris {
            // Parse the URL
            let url = Url::parse(uri)?;
            // Extract the secret from query parameters
            if let Some(secret) = url.query_pairs()
                .find(|(key, _)| key == "secret")
                .map(|(_, value)| value.into_owned()) {
                let mut account = AccountResponse::new(
                    &Account::new("", AccountKind::Login));
                account.label = Some(url.domain().unwrap_or("").to_string());
                account.otp = Some(secret.to_string());
                account.generated_otp = Some(TOTP::new(secret).generate(30, 0));
                accounts.push(account);
            }
        }
        Ok(accounts)
    }
}

#[async_trait]
impl OTPService for OTPServiceImpl {
    async fn generate_otp(&self, secret: &str) -> PassResult<u32> {
        Ok(TOTP::new(secret).generate(30, Utc::now().timestamp() as u64))
    }

    async fn convert_from_qrcode(&self, _ctx: &UserContext,
                                 _image_data: &[u8]) -> PassResult<Vec<AccountResponse>> {
        let _ = self.metrics.new_metric("convert_from_qrcode");
        let accounts = Vec::new();
        // let img = image::load_from_memory(image_data)?;
        // let luma_img = img.to_luma8();
        // let mut prep_img = PreparedImage::prepare(luma_img);
        // let grids = prep_img.detect_grids();
        //
        // for grid in grids {
        //     let (_meta, content) = grid.decode()?;
        //     for account in OTPServiceImpl::decode_otp(&content).await? {
        //         accounts.push(account);
        //     }
        // }
        Ok(accounts)
    }

    async fn convert_to_qrcode(&self, _ctx: &UserContext,
                               secrets: Vec<&str>) -> PassResult<Vec<u8>> {
        let _ = self.metrics.new_metric("convert_to_qrcode");
        let combined_secrets = secrets.join("\n");
        let code = QrCode::new(combined_secrets).map_err(|e| e.to_string())?;
        let __image: ImageBuffer<Luma<u8>, Vec<u8>> = code.render::<Luma<u8>>().build();

        let bytes: Vec<u8> = Vec::new();
        // image
        //     .write(&mut bytes, image::ImageOutputFormat::Png)
        //     .map_err(|e| e.to_string())?;
        Ok(bytes)
    }

    /// Extract OTP secret from QRCode file
    async fn convert_from_qrcode_file(&self, ctx: &UserContext,
                                      in_path: &Path) -> PassResult<Vec<AccountResponse>> {
        let _ = self.metrics.new_metric("convert_from_qrcode_file");
        let image_data = fs::read(in_path)?;
        self.convert_from_qrcode(ctx, &image_data).await
    }

    /// Create QRCode image file for OTP secrets
    async fn convert_to_qrcode_file(&self,
                                    ctx: &UserContext, secrets: Vec<&str>,
                                    out_path: &Path) -> PassResult<()> {
        let _ = self.metrics.new_metric("convert_to_qrcode_file");
        let image_data = self.convert_to_qrcode(ctx, secrets).await?;
        fs::write(out_path, image_data)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::domain::models::PassConfig;
    use crate::service::factory::create_otp_service;
    use crate::service::otp_service_impl::OTPServiceImpl;

    #[tokio::test]
    async fn test_should_generate_otp() {
        let config = PassConfig::new();
        // GIVEN otp-service
        let otp_service = create_otp_service(&config).await.unwrap();
        let code = otp_service.generate_otp("JBSWY3DPEHPK3PXP").await.unwrap();
        assert!(code > 0);
    }

    #[tokio::test]
    async fn test_should_convert_otp() {
        // GIVEN otp-service
        let data = "otpauth://totp/Example:alice@google.com?issuer=Example&period=30&secret=JBSWY3DPEHPK3PXP";
        let res = OTPServiceImpl::decode_otp(data).await.unwrap();
        assert_eq!(1, res.len());
        assert_eq!("JBSWY3DPEHPK3PXP", res[0].otp.clone().unwrap());
    }
}
