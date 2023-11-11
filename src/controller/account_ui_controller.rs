use std::collections::HashMap;
use std::convert::Infallible;
use std::time::Duration;

use actix_multipart::Multipart;
use actix_web::{Error, error, get, HttpResponse, Responder, web};
use actix_web::http::header::CONTENT_DISPOSITION;
use actix_web::web::Bytes;
use actix_web_lab::__reexports::futures_util;
use actix_web_lab::sse;
use actix_web_lab::sse::Sse;
use futures::{StreamExt, TryStreamExt};

use crate::controller::models::{AccountResponse, Authenticated};
use crate::domain::models::{Account, EncodingScheme, ProgressStatus};
use crate::service::locator::ServiceLocator;

const MAX_SIZE: usize = 1_048_576; // 1MB in bytes

#[get("/ui/accounts/{id}")]
pub async fn get_account(
    service_locator: web::Data<ServiceLocator>,
    path: web::Path<String>,
    auth: Authenticated,
) -> Result<HttpResponse, Error> {
    let account_id = path.into_inner();
    let account = service_locator
        .account_service
        .get_account(&auth.context, &account_id)
        .await?;
    let res = AccountResponse::new(&account);
    Ok(HttpResponse::Ok().json(res))
}

pub async fn create_account(
    service_locator: web::Data<ServiceLocator>,
    mut payload: Multipart,
    auth: Authenticated,
) -> Result<HttpResponse, Error> {
    let account = Account::from_multipart(&mut payload, true).await?;
    let _ = service_locator
        .account_service
        .create_account(&auth.context, &account)
        .await?;
    Ok(HttpResponse::Ok().json(AccountResponse::new(&account)))
}

pub async fn update_account(
    service_locator: web::Data<ServiceLocator>,
    mut payload: Multipart,
    auth: Authenticated,
) -> Result<HttpResponse, Error> {
    let account = Account::from_multipart(&mut payload, false).await?;
    let _ = service_locator
        .account_service
        .update_account(&auth.context, &account)
        .await?;
    Ok(HttpResponse::Ok().finish())
}

pub async fn import_accounts(
    service_locator: web::Data<ServiceLocator>,
    path: web::Path<String>,
    query: web::Query<HashMap<String, String>>,
    mut payload: Multipart,
    auth: Authenticated,
) -> Result<impl Responder, Error> {
    let vault_id = path.into_inner();
    let password = query.get("password").map(|s| s.into());
    let mut buffer = Vec::new();

    while let Ok(Some(mut field)) = payload.try_next().await {
        while let Some(chunk) = field.next().await {
            let data = chunk.unwrap();
            if (buffer.len() + data.len()) > MAX_SIZE {
                return Err(error::ErrorBadRequest("CSV File payload is too large"));
            }
            buffer.extend_from_slice(&data);
        }
    }

    let event_stream = futures_util::stream::iter([Ok::<_, Infallible>(sse::Event::Data(
        sse::Data::new(format!("{}\n\n", 50))
    ))]);


    let _res = service_locator.import_export_service.import_accounts(
        &auth.context,
        Some(vault_id.clone()),
        None,
        password,
        EncodingScheme::Base64,
        &buffer,
        Box::new(|status| match status {
            ProgressStatus::Started { .. } => {
                //let _ = tx.send(sse::Data::new("progress").event("0").into());
                //events.push(sse::Data::new(format!("{}\n\n", 50)));
            }
            ProgressStatus::Updated { current, total } => {
                let _progress = if total > 0 { current / total } else { 0 };
                //event_stream.update(Bytes::from(format!("data: {}\n\n", progress)));
                //let _ = tx.send(sse::Data::new("progress").event(progress.to_string()).into());
            }
            ProgressStatus::Completed => {
                //let _ = tx.send(sse::Data::new("progress").event("100").into());
                //event_stream.update(Bytes::from(format!("data: {}\n\n", 100)));
            }
            ProgressStatus::Failed(_) => {
                //let _ = tx.send(sse::Data::new("progress").event("100").into());
                //event_stream.update(Bytes::from(format!("data: {}\n\n", 100)));
            }
        }),
    ).await?;
    Ok(Sse::from_stream(event_stream).with_keep_alive(Duration::from_secs(1)))
}

pub async fn export_accounts(
    service_locator: web::Data<ServiceLocator>,
    path: web::Path<String>,
    query: web::Query<HashMap<String, String>>,
    auth: Authenticated,
) -> Result<impl Responder, Error> {
    let password = query.get("password").map(|s| s.into());
    let vault_id = path.into_inner();
    let encoding = EncodingScheme::Base64;
    let (_, bytes_csv) = service_locator.import_export_service.export_accounts(
        &auth.context,
        &vault_id,
        password.clone(),
        encoding,
        Box::new(|status| match status {
            ProgressStatus::Started { .. } => {}
            ProgressStatus::Updated { .. } => {}
            ProgressStatus::Completed => {}
            ProgressStatus::Failed(_) => {}
        }),
    ).await?;
    let file = if password == None {
        format!("exported_accounts_{}.csv", &vault_id)
    } else {
        format!("exported_accounts_{}_encrypted.csv", &vault_id)
    };

    Ok(HttpResponse::Ok()
        .append_header((CONTENT_DISPOSITION, file.as_str()))
        .body(Bytes::from(bytes_csv)))
}

pub async fn delete_account(
    service_locator: web::Data<ServiceLocator>,
    path: web::Path<String>,
    auth: Authenticated,
) -> Result<HttpResponse, Error> {
    let account_id = path.into_inner();
    let _ = service_locator
        .account_service
        .delete_account(&auth.context, &account_id)
        .await?;
    Ok(HttpResponse::Ok().finish())
}