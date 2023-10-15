use crate::domain::models::{PassResult, PasswordAnalysis, PasswordPolicy};
use crate::hibp;
use crate::service::PasswordService;
use async_trait::async_trait;

#[derive(Clone)]
pub(crate) struct PasswordServiceImpl {}

impl PasswordServiceImpl {
    pub(crate) fn new() -> Self {
        Self {}
    }
}

#[async_trait]
impl PasswordService for PasswordServiceImpl {
    async fn generate_memorable_password(&self) -> Option<String> {
        let pws = PasswordPolicy::new();
        pws.generate_strong_memorable_password(3)
    }

    async fn generate_random_password(&self) -> Option<String> {
        let pws = PasswordPolicy::new();
        pws.generate_strong_random_password()
    }

    async fn analyze_password(&self, password: &str) -> PassResult<PasswordAnalysis> {
        Ok(PasswordPolicy::analyze_password(password))
    }

    async fn password_compromised(&self, password: &str) -> PassResult<bool> {
        hibp::password_compromised(password).await
    }
}

#[cfg(test)]
mod tests {
    use crate::domain::models::{PassConfig, PasswordStrength};
    use crate::service::factory::create_password_service;

    #[tokio::test]
    async fn test_generate_memorable_password() {
        let config = PassConfig::new();
        let pws = create_password_service(&config).await.unwrap();
        let password = pws.generate_memorable_password().await.unwrap();
        let analysis = pws.analyze_password(&password).await.unwrap();
        assert_eq!(PasswordStrength::STRONG, analysis.strength);
        assert!(analysis.entropy > 80.0);
    }

    #[tokio::test]
    async fn test_should_random_generate_password() {
        let config = PassConfig::new();
        let pws = create_password_service(&config).await.unwrap();
        let password = pws.generate_random_password().await.unwrap();
        let analysis = pws.analyze_password(&password).await.unwrap();
        assert_eq!(PasswordStrength::STRONG, analysis.strength);
        assert!(analysis.entropy > 80.0);
    }

    #[tokio::test]
    async fn test_should_check_for_password_compromised() {
        let config = PassConfig::new();
        let pws = create_password_service(&config).await.unwrap();
        let ok = pws.password_compromised("password").await.unwrap();
        assert!(ok);
    }
}
