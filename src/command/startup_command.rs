use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;

use actix_cors::Cors;
use actix_files::{Files, NamedFile};
use actix_session::config::PersistentSession;
use actix_session::SessionMiddleware;
use actix_session::storage::CookieSessionStore;
use actix_web::{App, http, HttpResponse, HttpServer, middleware, web};
use actix_web::cookie::Key;
use actix_web_prom::PrometheusMetricsBuilder;
use openssl::pkey::{PKey, Private};
use openssl::ssl::{SslAcceptor, SslAcceptorBuilder, SslMethod};
use rustls::{Certificate, PrivateKey, ServerConfig};
use rustls_pemfile::{certs, pkcs8_private_keys};
use time::Duration;

use crate::auth::auth_middleware;
use crate::controller::{account_api_controller, account_ui_controller, audit_api_controller, audit_ui_controller, auth_api_controller, categories_api_controller, categories_ui_controller, dashboard_ui_controller, encryption_api_controller, import_export_api_controller, otp_api_controller, otp_ui_controller, password_api_controller, password_ui_controller, share_api_controller, share_ui_controller, user_api_controller, user_ui_controller, vault_api_controller, webauthn_ui_controller};
use crate::controller::auth_ui_controller::{handle_user_signin, handle_user_signout, handle_user_signup, user_mfa_recover, user_mfa_signin, user_signin, user_signup};
use crate::controller::user_ui_controller::generate_api_token;
use crate::controller::vault_ui_controller::home_page;
use crate::domain::error::PassError;
use crate::domain::models::{PassConfig, PassResult};
use crate::service::locator::ServiceLocator;

/*
We put self-signed certificate in this directory as an example but your browser will complain that
connections to the server aren't secure. We recommend to use [`mkcert`] to trust it.
To use a local CA, you should run:

```sh
mkcert -install
brew install mkcert
```

If you want to generate your own private key/certificate pair, then run:

```sh
mkcert -key-file key.pem -cert-file cert.pem 127.0.0.1 localhost
mkcert -key-file key-pass.pem -cert-file cert-pass.pem  127.0.0.1 localhost
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain cert-pass.pem
```

A new `key.pem` and `cert.pem` will be saved to the current directory. You will then need to modify `main.rs` where indicated.

## Self-Signed Encrypted Private Key Command

```sh
openssl req -x509 -nodes -newkey rsa:4096 -keyout key-pass.pem -out cert-pass.pem -days 365
```

openssl req -x509 -newkey rsa:4096 -keyout key-pass.pem -out cert-pass.pem -sha256 -days 365
[`mkcert`]: https://github.com/FiloSottile/mkcert
*/

pub async fn execute(config: PassConfig) -> PassResult<()> {
    let service_locator = ServiceLocator::new(&config).await?;
    let http_port = config.http_port();
    let https_port = config.https_port();
    let prometheus = PrometheusMetricsBuilder::new("api")
        .endpoint("/metrics")
        .build()
        .expect("failed to initialize prometheus");
    let server = HttpServer::new(move || {
        let secret_key = Key::derive_from(&config.session_key);
        App::new()
            .app_data(web::Data::new(service_locator.clone()))
            .route("/favicon.ico", web::get().to(fav_icon))
            .service(
                Files::new("/assets", "./assets")
            )
            .wrap(
                Cors::default() // allowed_origin return access-control-allow-origin: * by default
                    .allowed_origin(&format!("http://127.0.0.1:{}", http_port.clone()))
                    .allowed_origin(&format!("https://127.0.0.1:{}", https_port.clone()))
                    .allowed_origin(&format!("http://localhost:{}", http_port.clone()))
                    .allowed_origin(&format!("https://localhost:{}", https_port.clone()))
                    .send_wildcard()
                    .allowed_methods(vec!["GET", "POST", "PUT", "DELETE"])
                    .allowed_headers(vec![
                        http::header::AUTHORIZATION,
                        http::header::ACCEPT,
                        http::header::CONTENT_TYPE,
                    ])
                    .max_age(3600), // for cors
            )
            .wrap(middleware::Logger::default())
            .wrap(auth_middleware::Authentication)
            .wrap(prometheus.clone())
            //.wrap(SessionMiddleware::new(MemorySession::new(), secret_key))
            .wrap(
                SessionMiddleware::builder(
                    CookieSessionStore::default(),
                    secret_key,
                )
                    .session_lifecycle(PersistentSession::default()
                        .session_ttl(Duration::minutes(config.session_timeout_minutes)))
                    .cookie_secure(true)
                    .cookie_http_only(true)
                    //.cookie_domain(Some(config.domain.clone()))
                    .cookie_path("/".to_owned()) // Apply cookie to the entire application
                    .build(),
            )
            .configure(config_services)
    });

    match load_rustls_config(&config) {
        Ok(server_config) => {
            log::info!("starting TLS based API server on {}", https_port);
            server
                .bind_rustls_021(&format!("0.0.0.0:{}", https_port.clone()), server_config)?
                .workers(4)
                .run()
                .await?;
        }
        Err(_err) => {
            if let Err(err) = load_rustls_config(&config) {
                log::warn!("failed to start TLS based API server on {} due to {:?}", https_port, err)
            }
            match ssl_builder(&config) {
                Ok(builder) => {
                    log::info!("starting openSSL based API server on {}", https_port);
                    server
                        .bind_openssl(&format!("0.0.0.0:{}", https_port.clone()), builder)?
                        .workers(4)
                        .run()
                        .await?;
                }
                Err(err) => {
                    log::warn!("failed to start openSSL based API server on {} due to {:?}", https_port, err);
                    log::info!("starting HTTP based API server on {}", http_port);
                    server.bind(("0.0.0.0", http_port))?.run().await?;
                }
            };
        }
    };

    Ok(())
}

async fn fav_icon() -> actix_web::Result<NamedFile> {
    Ok(NamedFile::open("./assets/images/favicon.ico")?)
}

async fn health() -> HttpResponse {
    HttpResponse::Ok().finish()
}

// configure routes for services
fn config_services(service_config: &mut web::ServiceConfig) {
    service_config.service(web::resource("/health").to(health));

    // API Controllers
    // auth and user controller
    service_config.service(auth_api_controller::signup_user)
        .service(auth_api_controller::signin_user)
        .service(auth_api_controller::signout_user)
        .service(auth_api_controller::recover_mfa)
        .service(user_api_controller::get_user)
        .service(user_api_controller::update_user)
        .service(user_api_controller::search_usernames)
        .service(user_api_controller::delete_user)
        .service(user_api_controller::asymmetric_user_encrypt)
        .service(user_api_controller::asymmetric_user_decrypt);

    // vault controller
    service_config.service(vault_api_controller::create_vault)
        .service(vault_api_controller::get_vault)
        .service(vault_api_controller::get_vaults)
        .service(vault_api_controller::update_vault)
        .service(vault_api_controller::delete_vault)
        .service(vault_api_controller::analyze_vault_passwords);

    // account controller
    service_config.service(account_api_controller::create_account)
        .service(account_api_controller::get_account)
        .service(account_api_controller::get_accounts)
        .service(account_api_controller::update_account)
        .service(account_api_controller::delete_account);

    // category controller
    service_config.service(categories_api_controller::create_category)
        .service(categories_api_controller::get_categories)
        .service(categories_api_controller::delete_category);

    // password controller
    service_config.service(password_api_controller::generate_memorable_password)
        .service(password_api_controller::generate_random_password)
        .service(password_api_controller::password_compromised)
        .service(password_api_controller::email_compromised)
        .service(password_api_controller::check_password_strength)
        .service(password_api_controller::analyze_all_passwords);

    // import-export controller
    service_config.service(import_export_api_controller::import_accounts)
        .service(import_export_api_controller::export_accounts);

    // encryption-controller
    service_config.service(encryption_api_controller::generate_private_public_keys)
        .service(encryption_api_controller::asymmetric_encrypt)
        .service(encryption_api_controller::asymmetric_decrypt)
        .service(encryption_api_controller::symmetric_encrypt)
        .service(encryption_api_controller::symmetric_decrypt);

    // share-controller
    service_config.service(share_api_controller::share_vault)
        .service(share_api_controller::share_account);

    // otp-controller
    service_config.service(otp_api_controller::generate_otp);
    service_config.service(otp_api_controller::generate_user_otp);
    service_config.service(otp_api_controller::generate_account_otp);

    // audit-logs-controller
    service_config.service(audit_api_controller::audit_logs);

    //----------------------- UI Controllers
    service_config.service(web::resource("/").route(web::get().to(home_page)));
    service_config.service(web::resource("/ui/signin")
        .route(web::get().to(user_signin))
        .route(web::post().to(handle_user_signin)));
    service_config.service(web::resource("/ui/mfa_signin")
        .route(web::get().to(user_mfa_signin)));
    service_config.service(web::resource("/ui/signup")
        .route(web::get().to(user_signup))
        .route(web::post().to(handle_user_signup)));
    service_config.service(web::resource("/ui/signout").route(web::get().to(handle_user_signout)));
    service_config.service(web::resource("/ui/api_token").route(web::get().to(generate_api_token)));
    service_config.service(web::resource("/ui/users/autocomplete").route(web::get().to(user_ui_controller::autocomplete_users)));
    service_config.service(web::resource("/ui/users/profile")
        .route(web::get().to(user_ui_controller::user_profile))
        .route(web::post().to(user_ui_controller::update_user_profile))
    );

    service_config.service(web::resource("/ui/webauthn/register_start").route(web::get().to(webauthn_ui_controller::start_register)));
    service_config.service(web::resource("/ui/webauthn/register_finish").route(web::post().to(webauthn_ui_controller::finish_register)));
    service_config.service(web::resource("/ui/webauthn/login_start").route(web::get().to(webauthn_ui_controller::start_authentication)));
    service_config.service(web::resource("/ui/webauthn/login_finish").route(web::post().to(webauthn_ui_controller::finish_authentication)));
    service_config.service(web::resource("/ui/webauthn/recover")
        .route(web::get().to(user_mfa_recover))
        .route(web::post().to(webauthn_ui_controller::recover_mfa))
    );
    service_config.service(web::resource("/ui/webauthn/unregister").route(web::post().to(webauthn_ui_controller::unregister_mfa_key)));

    // ui-account-controller
    // accounts
    service_config.route("/ui/accounts/update", web::post().to(account_ui_controller::update_account));
    service_config.route("/ui/accounts/create", web::post().to(account_ui_controller::create_account));
    service_config.route("/ui/accounts/{id}/delete", web::delete().to(account_ui_controller::delete_account));
    service_config.route("/ui/vaults/{vault_id}/accounts/import", web::post().to(account_ui_controller::import_accounts));

    // vaults
    service_config.service(web::resource("/ui/vaults/{vault_id}/accounts/export")
        .route(web::get().to(account_ui_controller::export_accounts)));
    service_config.service(account_ui_controller::get_account);

    // sharing
    service_config.route("/ui/vaults/{vault_id}/share", web::post().to(share_ui_controller::share_vault));
    service_config.route("/ui/vaults/{vault_id}/accounts/{id}/share", web::post().to(share_ui_controller::share_account));

    // dashboard
    service_config.route("/ui/dashboard", web::get().to(dashboard_ui_controller::dashboard_page));

    // ui password
    service_config.route("/ui/password/generate", web::get().to(password_ui_controller::generate_password_page));
    service_config.route("/ui/password/generate", web::post().to(password_ui_controller::generate_password));
    service_config.route("/ui/password/schedule_password_analysis", web::post().to(password_ui_controller::schedule_password_analysis));

    // ui categories
    service_config.route("/ui/categories", web::get().to(categories_ui_controller::categories_page));
    service_config.route("/ui/categories/{name}", web::post().to(categories_ui_controller::create_category));
    service_config.route("/ui/categories/{name}", web::delete().to(categories_ui_controller::delete_category));

    // otp
    service_config.route("/ui/otp/generate", web::get().to(otp_ui_controller::generate_otp));

    // ui audit logs
    service_config.route("/ui/audit_logs", web::get().to(audit_ui_controller::audit_logs));
}

fn ssl_builder(config: &PassConfig) -> PassResult<SslAcceptorBuilder> {
    // build TLS config from files
    let mut builder = SslAcceptor::mozilla_intermediate(SslMethod::tls()).unwrap();
    if let (Some(cert_file), Some(key_file)) = (&config.cert_file, &config.key_file) {
        if !Path::new(cert_file).exists() {
            return Err(PassError::runtime(format!("could not open cert_file {:?}", cert_file).as_str(), None));
        }
        if !Path::new(key_file).exists() {
            return Err(PassError::runtime(format!("could not open key_file {:?}", key_file).as_str(), None));
        }
        // use else block if you generate your own key+cert with `mkcert`.
        if let Some(key_password) = &config.key_password {
            // set the encrypted private key
            let pkey: PKey<Private> =
                load_encrypted_private_key(key_file.as_os_str().to_str().unwrap_or(""), key_password.as_str())?;
            builder.set_private_key(&pkey)?;
        } else {
            // set the unencrypted private key
            builder.set_private_key_file(key_file.as_os_str(), openssl::ssl::SslFiletype::PEM)?;
        }

        // set the certificate chain file location
        builder.set_certificate_chain_file(cert_file.as_os_str())?;

        Ok(builder)
    } else {
        Err(PassError::runtime("failed to setup ssl", None))
    }
}

fn load_encrypted_private_key(key_file: &str, key_password: &str) -> PassResult<PKey<Private>> {
    let mut file = File::open(key_file)?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;
    Ok(PKey::private_key_from_pem_passphrase(
        &buffer,
        key_password.as_bytes(),
    )?)
}

fn load_rustls_config(config: &PassConfig) -> PassResult<ServerConfig> {
    // init server config builder with safe defaults
    let server_config = ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth();

    if let (Some(cert_file), Some(key_file)) = (&config.cert_file, &config.key_file) {
        if !Path::new(cert_file).exists() {
            return Err(PassError::runtime(format!("could not open cert_file {:?}", cert_file).as_str(), None));
        }
        if !Path::new(key_file).exists() {
            return Err(PassError::runtime(format!("could not open key_file {:?}", key_file).as_str(), None));
        }
        // load TLS key/cert files
        let cert_file = &mut BufReader::new(File::open(cert_file.as_os_str())?);
        let key_file = &mut BufReader::new(File::open(key_file.as_os_str())?);

        // convert files to key/cert objects
        let cert_chain = certs(cert_file)?.into_iter().map(Certificate).collect();
        let mut keys: Vec<PrivateKey> = pkcs8_private_keys(key_file)?
            .into_iter()
            .map(PrivateKey)
            .collect();

        // exit if no keys could be parsed
        if keys.is_empty() {
            return Err(PassError::runtime(
                "could not locate PKCS 8 private keys.",
                None,
            ));
        }
        Ok(server_config.with_single_cert(cert_chain, keys.remove(0))?)
    } else {
        Err(PassError::runtime("failed to setup tls", None))
    }
}

#[cfg(test)]
mod tests {
    use crate::command::startup_command::load_rustls_config;
    use crate::domain::models::PassConfig;

    #[tokio::test]
    async fn test_should_load_rustls_config_without_cert_key_file() {
        let config = PassConfig::new();
        let res = load_rustls_config(&config);
        assert!(res.is_err())
    }

    #[tokio::test]
    async fn test_should_load_rustls_config_with_cert_key_file() {
        let mut config = PassConfig::new();
        config.cert_file = Some("config/cert-pass.pem".into());
        config.key_file = Some("config/key-pass.pem".into());
        let res = load_rustls_config(&config);
        assert!(res.is_ok())
    }
}
