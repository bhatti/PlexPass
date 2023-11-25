// FIDO2 is an authentication standard that includes the WebAuthn and CTAP
// (Client-to-Authenticator Protocol) specifications.

use std::collections::HashMap;
use actix_session::Session;
use actix_web::web::{Json};
use actix_web::{http, HttpResponse, Responder, web, Error};
use webauthn_rs::prelude::{
    CreationChallengeResponse, PublicKeyCredential,
    RegisterPublicKeyCredential, RequestChallengeResponse,
};

use crate::controller::models::{Authenticated, QueryRecoveryCode, QuerySecurityKeyId};
use crate::controller::USER_SESSION_KEY;
use crate::domain::models::{HardwareSecurityKey, PassResult};
use crate::service::locator::ServiceLocator;

// The first step a client (user) will carry out is requesting a credential to be
// registered. We need to provide a challenge for this. The work flow will be:
//
//          ┌───────────────┐     ┌───────────────┐      ┌───────────────┐
//          │ Authenticator │     │    Browser    │      │     Site      │
//          └───────────────┘     └───────────────┘      └───────────────┘
//                  │                     │                      │
//                  │                     │     1. Start Reg     │
//                  │                     │─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─▶│
//                  │                     │                      │
//                  │                     │     2. Challenge     │
//                  │                     │◀ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ┤
//                  │                     │                      │
//                  │  3. Select Token    │                      │
//             ─ ─ ─│◀ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─│                      │
//  4. Verify │     │                     │                      │
//                  │  4. Yield PubKey    │                      │
//            └ ─ ─▶│─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─▶                      │
//                  │                     │                      │
//                  │                     │  5. Send Reg Opts    │
//                  │                     │─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─▶│─ ─ ─
//                  │                     │                      │     │ 5. Verify
//                  │                     │                      │         PubKey
//                  │                     │                      │◀─ ─ ┘
//                  │                     │                      │─ ─ ─
//                  │                     │                      │     │ 6. Persist
//                  │                     │                      │       Credential
//                  │                     │                      │◀─ ─ ┘
//                  │                     │                      │
//                  │                     │                      │
//
// async fn start_registration(info: web::Json<RegistrationStartRequest>) -> HttpResponse {
//     let rp_id = "example.com";
//     let rp_origin = Url::parse("https://localhost:8080").expect("Invalid URL");
//     let mut builder = WebauthnBuilder::new(rp_id, &rp_origin).expect("Invalid configuration");
//     let webauthn = builder.build().expect("Invalid configuration");
//
//     let user = SimpleUser {
//         username: info.username.clone(),
//         user_id: info.username.as_bytes().to_vec(),
//         credentials: vec![],
//     };
//
//     // Get the challenge for this user
//     let (challenge, _) = webauthn.generate_challenge(&user).unwrap();
//
//     // Normally, store the challenge in a secure session or a database
//     // For simplicity, we skip that here
//
//     HttpResponse::Ok().json(challenge)
// }

// In this step, we are responding to the start reg(istration) request, and providing
// the challenge to the browser.
pub(crate) async fn start_register(
    service_locator: web::Data<ServiceLocator>,
    auth: Authenticated,
) -> PassResult<Json<CreationChallengeResponse>> {
    let ccr = service_locator.auth_service.start_register_key(&auth.context).await?;
    // NOTE: We shouldn't store reg_state in session because we are using cookies store.
    Ok(Json(ccr))
}

// 3. The browser has completed it's steps and the user has created a public key
// on their device. Now we have the registration options sent to us, and we need
// to verify these and persist them.
// 3. The browser has completed it's steps and the user has created a public key
// on their device. Now we have the registration options sent to us, and we need
// to verify these and persist them.

pub(crate) async fn finish_register(
    service_locator: web::Data<ServiceLocator>,
    auth: Authenticated,
    req: Json<RegisterPublicKeyCredential>,
    query: web::Query<HashMap<String, String>>,
) -> PassResult<Json<HardwareSecurityKey>> {
    let name = query.get("name").unwrap_or(&req.id).clone();
    let hardware_key = service_locator.auth_service.finish_register_key(&auth.context, &name, &req).await?;
    Ok(Json(hardware_key))
}

// 4. Now that our public key has been registered, we can authenticate a user and verify
// that they are the holder of that security token. The work flow is similar to registration.
//
//          ┌───────────────┐     ┌───────────────┐      ┌───────────────┐
//          │ Authenticator │     │    Browser    │      │     Site      │
//          └───────────────┘     └───────────────┘      └───────────────┘
//                  │                     │                      │
//                  │                     │     1. Start Auth    │
//                  │                     │─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─▶│
//                  │                     │                      │
//                  │                     │     2. Challenge     │
//                  │                     │◀ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ┤
//                  │                     │                      │
//                  │  3. Select Token    │                      │
//             ─ ─ ─│◀ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─│                      │
//  4. Verify │     │                     │                      │
//                  │    4. Yield Sig     │                      │
//            └ ─ ─▶│─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─▶                      │
//                  │                     │    5. Send Auth      │
//                  │                     │        Opts          │
//                  │                     │─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─▶│─ ─ ─
//                  │                     │                      │     │ 5. Verify
//                  │                     │                      │          Sig
//                  │                     │                      │◀─ ─ ┘
//                  │                     │                      │
//                  │                     │                      │
//
// The user indicates the wish to start authentication and we need to provide a challenge.

pub(crate) async fn start_authentication(
    service_locator: web::Data<ServiceLocator>,
    auth: Authenticated,
) -> PassResult<Json<RequestChallengeResponse>> {
    let ccr = service_locator.auth_service.start_key_authentication(&auth.context).await?;
    // NOTE: We shouldn't store reg_state in session because we are using cookies store.
    Ok(Json(ccr))
}

// 5. The browser and user have completed their part of the processing. Only in the
// case that the webauthn authenticate call returns Ok, is authentication considered
// a success. If the browser does not complete this call, or *any* error occurs,
// this is an authentication failure.

pub(crate) async fn finish_authentication(
    service_locator: web::Data<ServiceLocator>,
    auth: Authenticated,
    cred: Json<PublicKeyCredential>,
) -> PassResult<HttpResponse> {
    service_locator.auth_service.finish_key_authentication(
        &auth.context, &auth.user_token.login_session, &cred).await?;
    Ok(HttpResponse::Found().insert_header((http::header::LOCATION, "/")).finish())
}

pub async fn recover_mfa(
    service_locator: web::Data<ServiceLocator>,
    params: web::Form<QueryRecoveryCode>,
    auth: Authenticated,
    session: Session,
) -> Result<impl Responder, Error> {
    service_locator.auth_service.reset_mfa_keys(
        &auth.context, &params.recovery_code, &auth.user_token.login_session).await?;
    let _ = session.remove(USER_SESSION_KEY);
    Ok(HttpResponse::Found().insert_header((http::header::LOCATION, "/")).finish())
}

pub async fn unregister_mfa_key(
    service_locator: web::Data<ServiceLocator>,
    params: web::Query<QuerySecurityKeyId>,
    auth: Authenticated,
) -> Result<impl Responder, Error> {
    let (_, mut user) = service_locator.user_service.get_user(&auth.context, &auth.context.user_id).await?;
    user.remove_security_key(&params.id);
    let _ = service_locator
        .user_service
        .update_user(&auth.context, &user)
        .await?;
    Ok(HttpResponse::Found().insert_header((http::header::LOCATION, "/ui/users/profile")).finish())
}

#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn test_should_web_auth() {
        // .shutdown_timeout(60) // Graceful shutdown time for workers
        // .run();
        // thread::spawn(move || {
        //     thread::sleep(Duration::from_secs(30));
        //     info!("shutting down...");
        //     actix_rt::System::current().stop();
        // });
        //let _ = server.await;
        //assert!(false);
    }
}
