use async_trait::async_trait;
use prometheus::Registry;

use crate::domain::models::{PassConfig, PassResult};
use crate::manager::PasswordManager;
use crate::utils::metrics::PassMetrics;

pub struct PasswordManagerImpl {
    //store: Box<dyn PassStore + Send + Sync>,
    metrics: PassMetrics,
    config: PassConfig,
}

impl PasswordManagerImpl {
    pub fn new(
        config: &PassConfig,
        //store: Box<dyn PassStore + Send + Sync>,
        registry: &Registry,
    ) -> PassResult<Self> {
        Ok(PasswordManagerImpl {
            config: config.clone(),
            //store,
            metrics: PassMetrics::new("password_manager", registry)?,
        })
    }
}

#[async_trait]
impl PasswordManager for PasswordManagerImpl {}

#[cfg(test)]
mod tests {

    #[tokio::test]
    async fn test_should_auto_create_and_acquire_lock() {}
}
