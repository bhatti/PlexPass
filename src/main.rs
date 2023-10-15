extern crate diesel;
extern crate diesel_migrations;
extern crate dotenv;
extern crate lazy_static;

mod auth;
pub mod controller;
mod crypto;
mod dao;
mod domain;
mod hibp;
mod manager;
mod service;
mod store;
mod utils;

use clap::Parser;
pub use controller::api_startup;
use domain::args::{Args, CommandActions};
use env_logger::Env;
use prometheus::default_registry;

use crate::domain::models::PassConfig;

//#[tokio::main(worker_threads = 2)]

#[actix_web::main] // or #[tokio::main]
async fn main() -> std::io::Result<()> {
    // Loading .env into environment variable.
    dotenv::dotenv().ok();

    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));

    let config = PassConfig::new();

    api_startup::start_api_server(config)
        .await
        .expect("could not start API server");

    let args: Args = Args::parse();

    Ok(())
    // let mut config = PassConfig::new();
    // if let Some(custom) = &args.config {
    //     let body = fs::read_to_string(custom).expect("failed to parse config file");
    //     config = serde_yaml::from_str(body.as_str()).expect("failed to deserialize config file");
    // }
    //
    // log::info!("using config: {:?}", config);
    //
    // let store: Box<dyn LockStore + Send + Sync> = if config.is_fair_vault() {
    //     let fair_vault_repo = factory::build_fair_vault_repository(
    //         args.provider, &config)
    //         .await.expect("failed to create fair vault");
    //     Box::new(FairLockStore::new(
    //         &config,
    //         fair_vault_repo,
    //     ))
    // } else {
    //     let account_repo = factory::build_account_repository(&config)
    //         .await.expect("failed to build account dao");
    //     let vault_repo = factory::build_vault_repository(
    //         args.provider, &config)
    //         .await.expect("failed to build vault dao");
    //
    //     Box::new(DefaultLockStore::new(
    //         &config,
    //         account_repo,
    //         vault_repo))
    // };
    //
    // let locks_manager = PasswordManagerImpl::new(
    //     &config,
    //     store,
    //     &default_registry())
    //     .expect("failed to initialize lock manager");
    //
    // match &args.action {
    //     CommandActions::Acquire { key, lease, vault_max_size, data } => {
    //         let opts = AcquireLockOptionsBuilder::new(key.as_str())
    //             .with_lease_duration_secs(*lease)
    //             .with_vault_max_size(vault_max_size.unwrap_or(1))
    //             .with_opt_data(data)
    //             .build();
    //
    //         let account = locks_manager.acquire_lock(&opts).await
    //             .expect("failed to acquire lock");
    //         if args.json_output.unwrap_or(false) {
    //             println!("{}", serde_json::to_string(&account).unwrap());
    //         } else {
    //             log::info!("acquired lock {}", account);
    //         }
    //     }
    //     CommandActions::Heartbeat { key, version, lease, vault_key, data } => {
    //         let opts = SendHeartbeatOptionsBuilder::new(key, version)
    //             .with_lease_duration_secs(*lease)
    //             .with_opt_vault_key(vault_key)
    //             .with_opt_data(data)
    //             .build();
    //
    //         let account = locks_manager.send_heartbeat(&opts).await
    //             .expect("failed to renew lock");
    //         if args.json_output.unwrap_or(false) {
    //             println!("{}", serde_json::to_string(&account).unwrap());
    //         } else {
    //             log::info!("renewed lock {}", account);
    //         }
    //     }
    //     CommandActions::Release { key, version, vault_key, data } => {
    //         let opts = ReleaseLockOptionsBuilder::new(key, version)
    //             .with_opt_vault_key(vault_key)
    //             .with_opt_data(data)
    //             .build();
    //
    //         let done = locks_manager.release_lock(&opts).await
    //             .expect("failed to release lock");
    //         if args.json_output.unwrap_or(false) {
    //             println!("{}", serde_json::to_string(&done).unwrap());
    //         } else {
    //             log::info!("released lock {}", done);
    //         }
    //     }
    //     CommandActions::GetAccount { key } => {
    //         let account = locks_manager.get_account(key.as_str()).await
    //             .expect("failed to find lock");
    //         if args.json_output.unwrap_or(false) {
    //             println!("{}", serde_json::to_string(&account).unwrap());
    //         } else {
    //             log::info!("found lock {}", account);
    //         }
    //     }
    //     CommandActions::CreateAccount{ key, lease, data } => {
    //         let account = AcquireLockOptionsBuilder::new(key.as_str())
    //             .with_lease_duration_secs(*lease)
    //             .with_opt_data(data)
    //             .build().to_unlocked_account(config.get_tenant_id().as_str());
    //         let size = locks_manager.create_account(&account).await
    //             .expect("failed to create account");
    //         if args.json_output.unwrap_or(false) {
    //             println!("{}", serde_json::to_string(&account).unwrap());
    //         } else {
    //             log::info!("created account {}", size);
    //         }
    //     }
    //     CommandActions::DeleteAccount { key, version, vault_key } => {
    //         let size = locks_manager.delete_account(
    //             key.as_str(), version.as_str(), vault_key.as_ref().map(|s| s.clone())).await
    //             .expect("failed to delete lock");
    //         if args.json_output.unwrap_or(false) {
    //             println!("{}", serde_json::to_string(&size).unwrap());
    //         } else {
    //             log::info!("deleted lock {}", size);
    //         }
    //     }
    //     CommandActions::CreateVault { key, max_size, lease} => {
    //         let vault = VaultBuilder::new(key.as_str(), *max_size as i32)
    //             .with_lease_duration_secs(*lease)
    //             .build();
    //         let size = locks_manager.create_vault(&vault).await
    //             .expect("failed to create vault");
    //         if args.json_output.unwrap_or(false) {
    //             println!("{}", serde_json::to_string(&vault).unwrap());
    //         } else {
    //             log::info!("created vault {}", size);
    //         }
    //     }
    //     CommandActions::GetVault { key } => {
    //         let vault = locks_manager.get_vault(key.as_str()).await
    //             .expect("failed to find vault");
    //         if args.json_output.unwrap_or(false) {
    //             println!("{}", serde_json::to_string(&vault).unwrap());
    //         } else {
    //             log::info!("found vault {}", vault);
    //         }
    //     }
    //     CommandActions::DeleteVault { key, version } => {
    //         let size = locks_manager.delete_vault(key.as_str(), version.as_str()).await
    //             .expect("failed to delete vault");
    //         if args.json_output.unwrap_or(false) {
    //             println!("{}", serde_json::to_string(&size).unwrap());
    //         } else {
    //             log::info!("deleted vault {}", size);
    //         }
    //     }
    //     CommandActions::GetVaultaccounts { key } => {
    //         let accounts = locks_manager.get_vault_accounts(key.as_str()).await
    //             .expect("failed to find vault accounts");
    //         if args.json_output.unwrap_or(false) {
    //             println!("{}", serde_json::to_string(&accounts).unwrap());
    //         } else {
    //             log::info!("found {} vault accounts:", accounts.len());
    //             for account in accounts {
    //                 log::info!("\t{}", account);
    //             }
    //         }
    //     }
    // }
}
