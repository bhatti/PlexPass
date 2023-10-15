use crate::auth::auth_middleware;
use crate::auth::session::MemorySession;
use crate::controller::{
    account_controller, metrics_controller, password_controller, user_controller, vault_controller,
};
use crate::domain::error::PassError;
use crate::domain::models::{PassConfig, PassResult};
use crate::service::locator::ServiceLocator;
use actix_cors::Cors;
use actix_session::SessionMiddleware;
use actix_web::cookie::Key;
use actix_web::http::header;
use actix_web::{http, middleware, web, App, HttpResponse, HttpServer, Responder};
use actix_web_prom::PrometheusMetricsBuilder;
use openssl::pkey::{PKey, Private};
use openssl::ssl::{SslAcceptor, SslAcceptorBuilder, SslMethod};
use prometheus::{Encoder, TextEncoder};
use rustls::{Certificate, PrivateKey, ServerConfig};
use rustls_pemfile::{certs, pkcs8_private_keys};
use std::fs::File;
use std::io::{BufReader, Read};

/*
We put self-signed certificate in this directory as an example but your browser will complain that
connections to the server aren't secure. We recommend to use [`mkcert`] to trust it.
To use a local CA, you should run:

```sh
mkcert -install
```

If you want to generate your own private key/certificate pair, then run:

```sh
mkcert -key-file key.pem -cert-file cert.pem 127.0.0.1 localhost
```

A new `key.pem` and `cert.pem` will be saved to the current directory. You will then need to modify `main.rs` where indicated.

## Self-Signed Encrypted Private Key Command

```sh
openssl req -x509 -newkey rsa:4096 -keyout key-pass.pem -out cert-pass.pem -sha256 -days 365
```
openssl req -x509 -nodes -newkey rsa:4096 -keyout key-pass.pem -out cert-pass.pem -days 365

[`mkcert`]: https://github.com/FiloSottile/mkcert
*/

pub async fn start_api_server(config: PassConfig) -> PassResult<()> {
    let service_locator = ServiceLocator::new(&config).await?;
    //let service_locator = web::block(move || ServiceLocator::new(&config).await)?;
    let http_port = config.http_port();
    let https_port = config.https_port();
    let prometheus = PrometheusMetricsBuilder::new("api")
        .endpoint("/metrics")
        .build()
        .expect("failed to initialize prometheus");
    let server = HttpServer::new(move || {
        let session_key = Key::derive_from(&config.session_key);
        App::new()
            .app_data(web::Data::new(service_locator.clone()))
            .wrap(SessionMiddleware::new(MemorySession::new(), session_key))
            .wrap(
                Cors::default() // allowed_origin return access-control-allow-origin: * by default
                    .allowed_origin(&format!("http://127.0.0.1:{}", http_port.clone()))
                    .allowed_origin(&format!("http://127.0.0.1:{}", https_port.clone()))
                    .allowed_origin(&format!("http://localhost:{}", http_port.clone()))
                    .allowed_origin(&format!("http://localhost:{}", https_port.clone()))
                    .send_wildcard()
                    .allowed_methods(vec!["GET", "POST", "PUT", "DELETE"])
                    .allowed_headers(vec![
                        http::header::AUTHORIZATION,
                        http::header::ACCEPT,
                        http::header::CONTENT_TYPE,
                    ])
                    .max_age(3600),
            )
            .wrap(middleware::Logger::default())
            .wrap(auth_middleware::Authentication)
            .wrap(prometheus.clone())
            .configure(config_services)
    });

    if let Ok(server_config) = load_rustls_config(&config) {
        log::info!(
            "starting TLS based API server on {}, data-dir {}, hsm {}",
            https_port,
            &config.data_dir,
            &config.hsm_provider
        );
        server
            .bind_rustls_021(&format!("0.0.0.0:{}", https_port.clone()), server_config)?
            .workers(4)
            .run()
            .await?;
    } else if let Ok(builder) = ssl_builder(&config) {
        log::info!(
            "starting openSSL based API server on {}, data-dir {}, hsm {}",
            https_port,
            &config.data_dir,
            &config.hsm_provider
        );
        server
            .bind_openssl(&format!("0.0.0.0:{}", https_port.clone()), builder)?
            .workers(4)
            .run()
            .await?;
    } else {
        log::info!(
            "starting HTTP based API server on {}, data-dir {}, hsm {}",
            http_port,
            &config.data_dir,
            &config.hsm_provider
        );
        server.bind(("0.0.0.0", http_port.clone()))?.run().await?;
    }

    Ok(())
}

async fn health() -> HttpResponse {
    HttpResponse::Ok().finish()
}

// configure routes for services
pub fn config_services(cfg: &mut web::ServiceConfig) {
    cfg.service(web::resource("/health").to(health));
    // user controller
    cfg.service(user_controller::signup_user)
        .service(user_controller::signin_user)
        .service(user_controller::signout_user)
        .service(user_controller::get_user)
        .service(user_controller::update_user)
        .service(user_controller::delete_user);

    // vault controller
    cfg.service(vault_controller::create_vault)
        .service(vault_controller::get_vault)
        .service(vault_controller::get_vaults)
        .service(vault_controller::update_vault)
        .service(vault_controller::delete_vault);

    // account controller
    cfg.service(account_controller::create_account)
        .service(account_controller::get_account)
        .service(account_controller::get_accounts)
        .service(account_controller::update_account)
        .service(account_controller::delete_account);

    // password controller
    cfg.service(password_controller::generate_memorable_password)
        .service(password_controller::generate_random_password)
        .service(password_controller::password_compromised)
        .service(password_controller::analyze_password);
}

fn ssl_builder(config: &PassConfig) -> PassResult<SslAcceptorBuilder> {
    // build TLS config from files
    let mut builder = SslAcceptor::mozilla_intermediate(SslMethod::tls()).unwrap();
    if let (Some(cert_file), Some(key_file)) = (&config.cert_file, &config.key_file) {
        // use else block if you generate your own key+cert with `mkcert`.
        if let Some(key_password) = &config.key_password {
            // set the encrypted private key
            let pkey: PKey<Private> =
                load_encrypted_private_key(key_file.as_str(), key_password.as_str())?;
            builder.set_private_key(&pkey)?;
        } else {
            // set the unencrypted private key
            builder.set_private_key_file(key_file.as_str(), openssl::ssl::SslFiletype::PEM)?;
        }

        // set the certificate chain file location
        builder.set_certificate_chain_file(cert_file.as_str())?;

        Ok(builder)
    } else {
        Err(PassError::runtime("failed to setup ssl", None))
    }
}

fn load_encrypted_private_key(key_file: &str, key_password: &str) -> PassResult<PKey<Private>> {
    let mut file = File::open(key_file)?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;
    return Ok(PKey::private_key_from_pem_passphrase(
        &buffer,
        key_password.as_bytes(),
    )?);
}

fn load_rustls_config(config: &PassConfig) -> PassResult<ServerConfig> {
    // init server config builder with safe defaults
    let server_config = ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth();

    if let (Some(cert_file), Some(key_file)) = (&config.cert_file, &config.key_file) {
        // load TLS key/cert files
        let cert_file = &mut BufReader::new(File::open(cert_file.as_str())?);
        let key_file = &mut BufReader::new(File::open(key_file.as_str())?);

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
