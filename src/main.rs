extern crate diesel;
extern crate diesel_migrations;
extern crate dotenv;
extern crate lazy_static;
extern crate plexpass;

use std::fs;
use std::collections::HashMap;
use std::io::Write;

use clap::Parser;
use env_logger::Builder;

use plexpass::command::{analyze_all_vaults_passwords_command, analyze_vault_passwords_command, asymmetric_decrypt_command, asymmetric_encrypt_command, create_account_command, create_category_command, create_user_command, create_vault_command, delete_account_command, delete_category_command, delete_user_command, delete_vault_command, email_compromised_command, export_accounts_command, generate_otp_command, generate_password_command, generate_private_public_keys_command, get_account_command, get_accounts_command, get_categories_command, get_user_command, get_vault_command, get_vaults_command, import_accounts_command, password_compromised_command, password_strength_command, query_audit_logs_command, search_users_command, share_account_command, share_vault_command, startup_command, symmetric_decrypt_command, symmetric_encrypt_command, update_account_command, update_user_command, update_vault_command};
use plexpass::domain::args::{Args, CommandActions};

use crate::plexpass::domain::models::PassConfig;

#[actix_web::main] // or #[tokio::main]
async fn main() -> std::io::Result<()> {
    // Loading .env into environment variable.
    dotenv::dotenv().ok();

    Builder::from_env(env_logger::Env::new().default_filter_or("info"))
        .format(|buf, record| {
            // skip logging of any passwords
            if !regex::Regex::new(r".*password.*").unwrap().is_match(record.args().to_string().as_str()) {
                writeln!(buf, "{}", record.args())
            } else {
                Ok(())
            }
        })
        .init();

    let args: Args = Args::parse();
    let mut config = PassConfig::new();
    if let Some(custom) = &args.config {
        let body = fs::read_to_string(custom).expect("failed to parse config file");
        config = serde_yaml::from_str(body.as_str()).expect("failed to deserialize config file");
    }

    if let Some(ref data_dir) = args.data_dir {
        config.override_data_dir(data_dir);
    }

    if let CommandActions::Server { .. } = args.action {
        // validation later
    } else {
        config.validate().expect("could not setup system configuration");
    }

    match &args.action {
        CommandActions::Server {
            http_port,
            https_port,
            hsm_provider,
            domain,
            jwt_key,
            session_timeout_minutes,
            cert_file,
            key_file,
            key_password,
        } => {
            config.override_server_args(
                http_port,
                https_port,
                hsm_provider,
                domain,
                jwt_key,
                session_timeout_minutes,
                cert_file,
                key_file,
                key_password,
                &args.device_pepper_key,
            );
            config.validate().expect("could not setup system configuration");
            startup_command::execute(config)
                .await
                .expect("could not start API server");
        }
        CommandActions::CreateUser { .. } => {
            let master_password = args.master_password.clone().expect("Please specify master password with --master-password");
            let user = args.to_user().expect("Failed to initialize user");
            let _ = create_user_command::execute(
                config,
                &user,
                &master_password).await.expect("failed to create user");
            if args.json_output.unwrap_or(false) {
                println!("{}", serde_json::to_string(&user).unwrap());
            } else {
                log::info!("created user {:?}", &user);
            }
        }
        CommandActions::GetUser {
            user_id,
        } => {
            let master_username = args.master_username.clone().expect("Please specify username with --master-username");
            let master_password = args.master_password.clone().expect("Please specify master password with --master-password");
            let user = get_user_command::execute(
                config,
                &master_username,
                &master_password,
                user_id.clone())
                .await.expect("failed to get user");
            if args.json_output.unwrap_or(false) {
                println!("{}", serde_json::to_string(&user).unwrap());
            } else {
                log::info!("user info {:?}", &user);
            }
        }
        CommandActions::UpdateUser { .. } => {
            let master_password = args.master_password.clone().expect("Please specify master password with --master-password");
            let mut user = args.to_user().expect("Failed to initialize user");
            let size = update_user_command::execute(
                config,
                &mut user,
                &master_password).await.expect("failed to update user");
            if args.json_output.unwrap_or(false) {
                let res = HashMap::from([("updated", size == 1)]);
                println!("{}", serde_json::to_string(&res).unwrap());
            } else {
                log::info!("updated user");
            }
        }
        CommandActions::DeleteUser {
            user_id,
        } => {
            let master_username = args.master_username.clone().expect("Please specify username with --master-username");
            let master_password = args.master_password.clone().expect("Please specify master password with --master-password");
            let size = delete_user_command::execute(
                config,
                &master_username,
                &master_password,
                user_id.clone()).await.expect("failed to delete user");
            if args.json_output.unwrap_or(false) {
                let res = HashMap::from([("deleted", size == 1)]);
                println!("{}", serde_json::to_string(&res).unwrap());
            } else {
                log::info!("deleted user");
            }
        }
        CommandActions::CreateVault { .. } => {
            let master_username = args.master_username.clone().expect("Please specify username with --master-username");
            let master_password = args.master_password.clone().expect("Please specify master password with --master-password");
            let mut vault = args.to_vault().expect("Could not build vault");
            let size = create_vault_command::execute(
                config,
                &master_username,
                &master_password,
                &mut vault,
            ).await.expect("failed to create vault");
            if args.json_output.unwrap_or(false) {
                let res = HashMap::from([("created", size == 1)]);
                println!("{}", serde_json::to_string(&res).unwrap());
            } else {
                log::info!("created vault {:?}", vault);
            }
        }
        CommandActions::GetVault {
            vault_id,
        } => {
            let master_username = args.master_username.clone().expect("Please specify username with --master-username");
            let master_password = args.master_password.clone().expect("Please specify master password with --master-password");
            let vault = get_vault_command::execute(
                config,
                &master_username,
                &master_password,
                vault_id,
            ).await.expect("failed to get vault");
            if args.json_output.unwrap_or(false) {
                println!("{}", serde_json::to_string(&vault).unwrap());
            } else {
                log::info!("vault {:?}", vault);
            }
        }
        CommandActions::GetVaults {} => {
            let master_username = args.master_username.clone().expect("Please specify username with --master-username");
            let master_password = args.master_password.clone().expect("Please specify master password with --master-password");
            let vaults = get_vaults_command::execute(
                config,
                &master_username,
                &master_password,
            ).await.expect("failed to get vaults");
            if args.json_output.unwrap_or(false) {
                println!("{}", serde_json::to_string(&vaults).unwrap());
            } else {
                log::info!("vaults {:?}", vaults);
            }
        }
        CommandActions::UpdateVault { .. } => {
            let master_username = args.master_username.clone().expect("Please specify username with --master-username");
            let master_password = args.master_password.clone().expect("Please specify master password with --master-password");
            let mut vault = args.to_vault().expect("Could not build vault");
            let size = update_vault_command::execute(
                config,
                &master_username,
                &master_password,
                &mut vault,
            ).await.expect("failed to update vault");
            if args.json_output.unwrap_or(false) {
                let res = HashMap::from([("updated", size == 1)]);
                println!("{}", serde_json::to_string(&res).unwrap());
            } else {
                log::info!("updated vault {:?}", vault);
            }
        }
        CommandActions::DeleteVault {
            vault_id,
        } => {
            let master_username = args.master_username.clone().expect("Please specify username with --master-username");
            let master_password = args.master_password.clone().expect("Please specify master password with --master-password");
            let size = delete_vault_command::execute(
                config,
                &master_username,
                &master_password,
                vault_id,
            ).await.expect("failed to delete vault");
            if args.json_output.unwrap_or(false) {
                let res = HashMap::from([("deleted", size == 1)]);
                println!("{}", serde_json::to_string(&res).unwrap());
            } else {
                log::info!("deleted vault");
            }
        }
        CommandActions::CreateAccount { .. } => {
            let master_username = args.master_username.clone().expect("Please specify username with --master-username");
            let master_password = args.master_password.clone().expect("Please specify master password with --master-password");
            let account = args.to_account().expect("Failed to initialize account");
            let size = create_account_command::execute(
                config,
                &master_username,
                &master_password,
                &account,
            ).await.expect("failed to create account");
            if args.json_output.unwrap_or(false) {
                let res = HashMap::from([("created", size == 1)]);
                println!("{}", serde_json::to_string(&res).unwrap());
            } else {
                log::info!("created account {:?}", account);
            }
        }
        CommandActions::GetAccounts { vault_id, q } => {
            let master_username = args.master_username.clone().expect("Please specify username with --master-username");
            let master_password = args.master_password.clone().expect("Please specify master password with --master-password");
            let accounts = get_accounts_command::execute(
                config,
                &master_username,
                &master_password,
                vault_id,
                q.clone(),
            ).await.expect("failed to get accounts");
            if args.json_output.unwrap_or(false) {
                println!("{}", serde_json::to_string(&accounts).unwrap());
            } else {
                log::info!("accounts {:?}", accounts);
            }
        }
        CommandActions::GetAccount { account_id } => {
            let master_username = args.master_username.clone().expect("Please specify username with --master-username");
            let master_password = args.master_password.clone().expect("Please specify master password with --master-password");
            let account = get_account_command::execute(
                config,
                &master_username,
                &master_password,
                account_id,
            ).await.expect("failed to get account");
            if args.json_output.unwrap_or(false) {
                println!("{}", serde_json::to_string(&account).unwrap());
            } else {
                log::info!("account {:?}", account);
            }
        }
        CommandActions::UpdateAccount { .. } => {
            let master_username = args.master_username.clone().expect("Please specify username with --master-username");
            let master_password = args.master_password.clone().expect("Please specify master password with --master-password");
            let mut account = args.to_account().expect("Failed to initialize account");
            let size = update_account_command::execute(
                config,
                &master_username,
                &master_password,
                &mut account,
            ).await.expect("failed to update account");
            if args.json_output.unwrap_or(false) {
                let res = HashMap::from([("updated", size == 1)]);
                println!("{}", serde_json::to_string(&res).unwrap());
            } else {
                log::info!("updated account {:?}", account);
            }
        }
        CommandActions::DeleteAccount { account_id } => {
            let master_username = args.master_username.clone().expect("Please specify username with --master-username");
            let master_password = args.master_password.clone().expect("Please specify master password with --master-password");
            let size = delete_account_command::execute(
                config,
                &master_username,
                &master_password,
                account_id,
            ).await.expect("failed to delete account");
            if args.json_output.unwrap_or(false) {
                let res = HashMap::from([("deleted", size == 1)]);
                println!("{}", serde_json::to_string(&res).unwrap());
            } else {
                log::info!("deleted account");
            }
        }
        CommandActions::CreateCategory { name } => {
            let master_username = args.master_username.clone().expect("Please specify username with --master-username");
            let master_password = args.master_password.clone().expect("Please specify master password with --master-password");
            let size = create_category_command::execute(
                config,
                &master_username,
                &master_password,
                name,
            ).await.expect("failed to create category");
            if args.json_output.unwrap_or(false) {
                let res = HashMap::from([("created", size == 1)]);
                println!("{}", serde_json::to_string(&res).unwrap());
            } else {
                log::info!("created category: {:?}", size);
            }
        }
        CommandActions::GetCategories {} => {
            let master_username = args.master_username.clone().expect("Please specify username with --master-username");
            let master_password = args.master_password.clone().expect("Please specify master password with --master-password");
            let res = get_categories_command::execute(
                config,
                &master_username,
                &master_password,
            ).await.expect("failed to get categories");
            if args.json_output.unwrap_or(false) {
                println!("{}", serde_json::to_string(&res).unwrap());
            } else {
                log::info!("created category{:?}", res);
            }
        }
        CommandActions::DeleteCategory { name } => {
            let master_username = args.master_username.clone().expect("Please specify username with --master-username");
            let master_password = args.master_password.clone().expect("Please specify master password with --master-password");
            let size = delete_category_command::execute(
                config,
                &master_username,
                &master_password,
                name,
            ).await.expect("failed to delete category");
            if args.json_output.unwrap_or(false) {
                let res = HashMap::from([("deleted", size == 1)]);
                println!("{}", serde_json::to_string(&res).unwrap());
            } else {
                log::info!("delete category: {:?}", size);
            }
        }
        CommandActions::GeneratePrivatePublicKeys { password } => {
            let (sk, pk) = generate_private_public_keys_command::execute(
                config,
                password,
            ).await.expect("failed to generate private and public keys");
            if args.json_output.unwrap_or(false) {
                let res = HashMap::from([("secret_key", sk), ("public_key", pk)]);
                println!("{}", serde_json::to_string(&res).unwrap());
            } else {
                log::info!("generated private {:?} and public keys {:?}", sk, pk);
            }
        }
        CommandActions::AsymmetricEncrypt { public_key, in_path, out_path } => {
            asymmetric_encrypt_command::execute(
                config,
                public_key,
                in_path,
                out_path,
            ).await.expect("failed to encrypt file with public key");
            if args.json_output.unwrap_or(false) {} else {
                log::info!("encrypted {:?} file as {:?}", in_path, out_path);
            }
        }
        CommandActions::AsymmetricDecrypt { secret_key, in_path, out_path } => {
            asymmetric_decrypt_command::execute(
                config,
                secret_key,
                in_path,
                out_path,
            ).await.expect("failed to decrypt file with private key");
            if args.json_output.unwrap_or(false) {} else {
                log::info!("decrypted {:?} file as {:?}", in_path, out_path);
            }
        }
        CommandActions::SymmetricEncrypt { secret_key, in_path, out_path } => {
            symmetric_encrypt_command::execute(
                config,
                secret_key,
                in_path,
                out_path,
            ).await.expect("failed to encrypt file with symmetric_key key");
            if args.json_output.unwrap_or(false) {} else {
                log::info!("encrypted {:?} file as {:?}", in_path, out_path);
            }
        }
        CommandActions::SymmetricDecrypt { secret_key, in_path, out_path } => {
            symmetric_decrypt_command::execute(
                config,
                secret_key,
                in_path,
                out_path,
            ).await.expect("failed to decrypt file with symmetric_key key");
            if args.json_output.unwrap_or(false) {} else {
                log::info!("decrypted {:?} file as {:?}", in_path, out_path);
            }
        }
        CommandActions::ImportAccounts { vault_id, password, in_path } => {
            let master_username = args.master_username.clone().expect("Please specify username with --master-username");
            let master_password = args.master_password.clone().expect("Please specify master password with --master-password");
            let res = import_accounts_command::execute(
                config,
                &master_username,
                &master_password,
                vault_id,
                password,
                in_path,
            ).await.expect("failed to import accounts");
            if args.json_output.unwrap_or(false) {
                println!("{}", serde_json::to_string(&res).unwrap());
            } else {
                log::info!("import accounts from {:?}: {:?}", in_path, res);
            }
        }
        CommandActions::ExportAccounts { vault_id, password, out_path } => {
            let master_username = args.master_username.clone().expect("Please specify username with --master-username");
            let master_password = args.master_password.clone().expect("Please specify master password with --master-password");
            let _ = export_accounts_command::execute(
                config,
                &master_username,
                &master_password,
                vault_id,
                password,
                out_path,
            ).await.expect("failed to export accounts");
            if args.json_output.unwrap_or(false) {
                let res = HashMap::from([("exported", true)]);
                println!("{}", serde_json::to_string(&res).unwrap());
            } else {
                log::info!("export accounts to {:?}", out_path);
            }
        }
        CommandActions::GeneratePassword { .. } => {
            let policy = args.to_policy().expect("could not build password policy");
            let password = generate_password_command::execute(config, &policy)
                .await.expect("could not generate password");
            if args.json_output.unwrap_or(false) {
                let res = HashMap::from([("password", password)]);
                println!("{}", serde_json::to_string(&res).unwrap());
            } else {
                log::info!("password {:?}", password);
            }
        }
        CommandActions::PasswordCompromised { password } => {
            let compromised = password_compromised_command::execute(config, password)
                .await.expect("could not check password");
            if args.json_output.unwrap_or(false) {
                let res = HashMap::from([("compromised", compromised)]);
                println!("{}", serde_json::to_string(&res).unwrap());
            } else {
                log::info!("compromised {:?}", compromised);
            }
        }
        CommandActions::PasswordStrength { password } => {
            let strength = password_strength_command::execute(config, password)
                .await.expect("could not check password");
            if args.json_output.unwrap_or(false) {
                println!("{}", serde_json::to_string(&strength).unwrap());
            } else {
                log::info!("strength: {:?}", strength);
            }
        }
        CommandActions::EmailCompromised { email, hibp_api_key } => {
            let compromised = email_compromised_command::execute(config, email, hibp_api_key)
                .await.expect("could not check email");
            if args.json_output.unwrap_or(false) {
                let res = HashMap::from([("compromised", compromised)]);
                println!("{}", serde_json::to_string(&res).unwrap());
            } else {
                log::info!("compromised {:?}", compromised);
            }
        }
        CommandActions::GenerateOTP { account_id, otp_secret } => {
            let master_username = args.master_username.clone().expect("Please specify username with --master-username");
            let master_password = args.master_password.clone().expect("Please specify master password with --master-password");
            let otp_code = generate_otp_command::execute(
                config, &master_username, &master_password, account_id, otp_secret)
                .await.expect("could not generate otp code");
            if args.json_output.unwrap_or(false) {
                let res = HashMap::from([("otp_code", otp_code)]);
                println!("{}", serde_json::to_string(&res).unwrap());
            } else {
                log::info!("otp code: {:?}", otp_code);
            }
        }
        CommandActions::AnalyzeVaultPasswords { vault_id } => {
            let master_username = args.master_username.clone().expect("Please specify username with --master-username");
            let master_password = args.master_password.clone().expect("Please specify master password with --master-password");
            let analysis = analyze_vault_passwords_command::execute(
                config, &master_username, &master_password, vault_id)
                .await.expect("could not analyze vault passwords");
            if args.json_output.unwrap_or(false) {
                println!("{}", serde_json::to_string(&analysis).unwrap());
            } else {
                log::info!("analysis: {:?}", analysis);
            }
        }
        CommandActions::AnalyzeAllVaultsPasswords {} => {
            let master_username = args.master_username.clone().expect("Please specify username with --master-username");
            let master_password = args.master_password.clone().expect("Please specify master password with --master-password");
            let analysis = analyze_all_vaults_passwords_command::execute(
                config, &master_username, &master_password)
                .await.expect("could not analyze all vaults passwords");
            if args.json_output.unwrap_or(false) {
                println!("{}", serde_json::to_string(&analysis).unwrap());
            } else {
                log::info!("analysis: {:?}", analysis);
            }
        }
        CommandActions::SearchUsernames { q } => {
            let master_username = args.master_username.clone().expect("Please specify username with --master-username");
            let master_password = args.master_password.clone().expect("Please specify master password with --master-password");
            let usernames = search_users_command::execute(
                config, &master_username, &master_password, q)
                .await.expect("could not search usernames");
            if args.json_output.unwrap_or(false) {
                println!("{}", serde_json::to_string(&usernames).unwrap());
            } else {
                log::info!("usernames: {:?}", usernames);
            }
        }
        CommandActions::ShareVault { vault_id, target_username, read_only } => {
            let master_username = args.master_username.clone().expect("Please specify username with --master-username");
            let master_password = args.master_password.clone().expect("Please specify master password with --master-password");
            let size = share_vault_command::execute(
                config,
                &master_username,
                &master_password,
                vault_id,
                target_username,
                read_only,
            ).await.expect("failed to share vault");
            if args.json_output.unwrap_or(false) {
                let res = HashMap::from([("shared", true)]);
                println!("{}", serde_json::to_string(&res).unwrap());
            } else {
                log::info!("shared vault {:?}", size);
            }
        }
        CommandActions::ShareAccount { vault_id, account_id, target_username } => {
            let master_username = args.master_username.clone().expect("Please specify username with --master-username");
            let master_password = args.master_password.clone().expect("Please specify master password with --master-password");
            let size = share_account_command::execute(
                config,
                &master_username,
                &master_password,
                vault_id,
                account_id,
                target_username,
            ).await.expect("failed to share account");
            if args.json_output.unwrap_or(false) {
                let res = HashMap::from([("shared", true)]);
                println!("{}", serde_json::to_string(&res).unwrap());
            } else {
                log::info!("shared account {:?}", size);
            }
        }
        CommandActions::QueryAuditLogs { q, offset, limit } => {
            let master_username = args.master_username.clone().expect("Please specify username with --master-username");
            let master_password = args.master_password.clone().expect("Please specify master password with --master-password");
            let audit_logs = query_audit_logs_command::execute(
                config,
                &master_username,
                &master_password,
                offset,
                limit,
                q,
            ).await.expect("failed to query audit logs");
            if args.json_output.unwrap_or(false) {
                println!("{}", serde_json::to_string(&audit_logs.records).unwrap());
            } else {
                log::info!("audit logs {:?}", audit_logs);
            }
        }
    }

    Ok(())
}
