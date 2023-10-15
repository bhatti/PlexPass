use async_trait::async_trait;

pub mod password_manager;

#[async_trait]
pub trait PasswordManager {}
